"""Retrieval-augmented context for the SecureX assistant.

Documents are split into chunks with LangChain, embedded with Sentence
Transformers and stored in a persistent ChromaDB collection. If those optional
packages (requirements-ai.txt) or the embedding model are unavailable, a local
keyword retriever is used so the assistant keeps working.

Retrieved text is evidence only. It is passed to the language model inside
clearly marked untrusted-data blocks and is never treated as instructions.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger('securex')

STOPWORDS = {
    'the', 'and', 'for', 'are', 'was', 'what', 'why', 'how', 'can', 'does', 'did',
    'this', 'that', 'with', 'from', 'have', 'has', 'you', 'your', 'about', 'which',
    'who', 'when', 'where', 'should', 'would', 'could', 'there', 'their', 'them',
    'mean', 'means', 'tell', 'explain', 'please', 'into', 'its', 'not', 'any',
}


def _terms(text: str) -> set:
    """Lower-cased word stems used by the keyword fallback."""
    return {
        word[:6] for word in re.findall(r'[a-z0-9]{3,}', text.lower())
        if word not in STOPWORDS
    }


def _split_paragraphs(text: str, chunk_size: int) -> List[str]:
    """Dependency-free splitter: pack whole paragraphs up to chunk_size."""
    chunks, current = [], ''
    for paragraph in re.split(r'\n\s*\n', text):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        while len(paragraph) > chunk_size:
            chunks.append(paragraph[:chunk_size])
            paragraph = paragraph[chunk_size:]
        if current and len(current) + len(paragraph) + 2 > chunk_size:
            chunks.append(current)
            current = paragraph
        else:
            current = f'{current}\n\n{paragraph}' if current else paragraph
    if current:
        chunks.append(current)
    return chunks


def chunk_documents(documents: Iterable[Dict[str, str]], chunk_size: int = 900,
                    chunk_overlap: int = 120, use_langchain: bool = False) -> List[Dict[str, str]]:
    """Split documents at Markdown headings, then into bounded chunks.

    With use_langchain, sections are split by LangChain's
    RecursiveCharacterTextSplitter. That package eagerly imports
    sentence-transformers, so it is only used while building the vector
    index in the background, never on the startup path.
    """
    splitter = None
    if use_langchain:
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)

    chunks = []
    for document in documents:
        sections = re.split(r'(?m)^(?=#{1,3} )', document['text'])
        for section in sections:
            section = section.strip()
            if not section:
                continue
            heading_match = re.match(r'#{1,3} (.+)', section)
            heading = heading_match.group(1).strip() if heading_match else ''
            source = document.get('source', 'SecureX knowledge base')
            if heading and heading not in source:
                source = f'{source} > {heading}'
            pieces = splitter.split_text(section) if splitter else _split_paragraphs(section, chunk_size)
            for piece in pieces:
                chunk_id = hashlib.sha1(f"{document['id']}|{piece}".encode('utf-8')).hexdigest()
                chunks.append({'id': chunk_id, 'source': source, 'text': piece})
    return chunks


class SecurityRetriever:
    """Retrieve security context with ChromaDB, falling back to keywords."""

    def __init__(self, config: Dict[str, Any] | None = None, documents: Iterable[Dict[str, str]] = ()):
        self.config = config or {}
        self._source_documents = list(documents)
        self._chunk_size = int(self.config.get('chunk_size', 900))
        self._chunk_overlap = int(self.config.get('chunk_overlap', 120))
        # Keyword index, available immediately.
        self.documents = chunk_documents(self._source_documents, self._chunk_size, self._chunk_overlap)
        # Vector index chunks, built with LangChain when the store loads.
        self.vector_documents: List[Dict[str, str]] = []
        self.max_distance = float(self.config.get('max_distance', 0.65))
        self.collection = None
        self._model = None
        self._init_lock = threading.Lock()
        self._init_attempted = False

    @property
    def mode(self) -> str:
        return 'vector' if self.collection is not None else 'keyword'

    def warm_up(self) -> None:
        """Load the embedding model and index in the background at startup."""
        if self.config.get('rag_enabled', False):
            threading.Thread(target=self._ensure_vector_store, name='securex-rag-init', daemon=True).start()

    def _ensure_vector_store(self) -> None:
        if not self.config.get('rag_enabled', False):
            return
        with self._init_lock:
            if self._init_attempted:
                return
            self._init_attempted = True
            try:
                import chromadb
                from sentence_transformers import SentenceTransformer

                model_name = self.config.get('embedding_model', 'all-MiniLM-L6-v2')
                try:
                    # Prefer the cached model so the assistant works offline.
                    self._model = SentenceTransformer(model_name, local_files_only=True)
                except Exception:
                    self._model = SentenceTransformer(model_name)
                client = chromadb.PersistentClient(path=self.config.get('chroma_path', 'data/chroma_db'))
                collection = client.get_or_create_collection(
                    name=self.config.get('collection', 'securex_security_knowledge'),
                    embedding_function=None,
                    metadata={'hnsw:space': 'cosine'},
                )
                self.vector_documents = chunk_documents(
                    self._source_documents, self._chunk_size, self._chunk_overlap, use_langchain=True
                )
                self._sync(collection)
                self.collection = collection
                logger.info('SecureX RAG vector store ready (%d chunks)', len(self.vector_documents))
            except Exception as error:
                self.collection = None
                logger.warning('RAG vector store unavailable; using keyword retrieval: %s', error)

    def _embed(self, texts: List[str]) -> List[List[float]]:
        return self._model.encode(texts, normalize_embeddings=True).tolist()

    def _sync(self, collection) -> None:
        """Add new chunks and remove chunks whose source text changed."""
        wanted = {item['id']: item for item in self.vector_documents}
        existing = set(collection.get(include=[])['ids'])
        stale = list(existing - wanted.keys())
        if stale:
            collection.delete(ids=stale)
        missing = [item for chunk_id, item in wanted.items() if chunk_id not in existing]
        if missing:
            collection.upsert(
                ids=[item['id'] for item in missing],
                documents=[item['text'] for item in missing],
                embeddings=self._embed([item['text'] for item in missing]),
                metadatas=[{'source': item['source']} for item in missing],
            )

    def retrieve(self, query: str, limit: int = 4) -> List[Dict[str, Any]]:
        """Return relevant evidence snippets, never executable instructions."""
        self._ensure_vector_store()
        if self.collection is not None:
            try:
                result = self.collection.query(
                    query_embeddings=self._embed([query]),
                    n_results=min(limit, max(len(self.vector_documents), 1)),
                    include=['documents', 'metadatas', 'distances'],
                )
                items = []
                for text, metadata, distance in zip(
                    (result.get('documents') or [[]])[0],
                    (result.get('metadatas') or [[]])[0],
                    (result.get('distances') or [[]])[0],
                ):
                    if distance <= self.max_distance:
                        items.append({
                            'text': text,
                            'source': (metadata or {}).get('source', 'SecureX knowledge base'),
                            'score': round(1 - float(distance), 3),
                        })
                return items
            except Exception as error:
                logger.warning('RAG retrieval failed; using keyword retrieval: %s', error)

        return self._keyword_retrieve(query, limit)

    def _keyword_retrieve(self, query: str, limit: int) -> List[Dict[str, Any]]:
        query_terms = _terms(query)
        if not query_terms:
            return []
        scored = []
        for item in self.documents:
            overlap = len(query_terms & _terms(item['text']))
            if overlap:
                scored.append((overlap / len(query_terms), item))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [
            {'text': item['text'], 'source': item['source'], 'score': round(score, 3)}
            for score, item in scored[:limit]
            if score >= 0.25
        ]

    @staticmethod
    def format_context(items: List[Dict[str, Any]]) -> str:
        if not items:
            return 'No retrieved security documentation matched this question.'
        return '\n\n'.join(
            f"[Evidence source: {item['source']}]\n{item['text']}"
            for item in items
        )


def load_documents(knowledge: Dict[str, Dict[str, Any]], knowledge_dir: Optional[str] = None) -> List[Dict[str, str]]:
    """Build trusted application documents plus the configured knowledge folder."""
    documents = []
    for name, definition in knowledge.items():
        documents.append({
            'id': f'knowledge-{name.lower().replace(" ", "-")}',
            'source': f'SecureX knowledge base: {name}',
            'text': (
                f"Threat type: {name}. {definition.get('description', '')}. "
                f"Risks: {', '.join(definition.get('risks', []))}. "
                f"Prevention: {', '.join(definition.get('prevention', []))}."
            ),
        })

    if knowledge_dir and Path(knowledge_dir).is_dir():
        for path in sorted(Path(knowledge_dir).glob('**/*')):
            if path.suffix.lower() not in {'.md', '.txt'} or not path.is_file():
                continue
            try:
                documents.append({
                    'id': f'document-{path.as_posix()}',
                    'source': path.stem.replace('_', ' '),
                    'text': path.read_text(encoding='utf-8')[:50000],
                })
            except OSError as error:
                logger.warning('Could not load knowledge document %s: %s', path, error)
    return documents
