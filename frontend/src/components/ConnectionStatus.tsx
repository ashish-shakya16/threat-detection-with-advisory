import { useEffect, useState } from 'react';
import { socket } from '@/lib/socket';

type Status = 'connected' | 'connecting' | 'offline';

const LABELS: Record<Status, string> = {
  connected: 'Live updates on',
  connecting: 'Connecting…',
  offline: 'Live updates offline, retrying…',
};

export function ConnectionStatus() {
  const [status, setStatus] = useState<Status>(socket.connected ? 'connected' : 'connecting');

  useEffect(() => {
    const onConnect = () => setStatus('connected');
    const onDisconnect = () => setStatus('connecting');
    const onError = () => setStatus('offline');

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onError);
    // The socket may have connected before this component mounted.
    if (socket.connected) setStatus('connected');

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('connect_error', onError);
    };
  }, []);

  const connected = status === 'connected';
  return (
    <div className="flex items-center gap-2.5 rounded-md border border-border bg-muted/50 px-3 py-2.5 text-sm">
      <span className="relative flex h-2 w-2">
        {connected && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-60" />
        )}
        <span
          className={`relative inline-flex h-2 w-2 rounded-full ${
            connected ? 'bg-success' : status === 'offline' ? 'bg-destructive' : 'bg-warning'
          }`}
        />
      </span>
      <span className="font-medium text-muted-foreground">{LABELS[status]}</span>
    </div>
  );
}
