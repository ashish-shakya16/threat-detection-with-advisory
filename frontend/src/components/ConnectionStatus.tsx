import { useEffect, useState } from 'react';
import { socket } from '@/lib/socket';

export function ConnectionStatus() {
  const [connected, setConnected] = useState(socket.connected);

  useEffect(() => {
    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
    };
  }, []);

  return (
    <div className="flex items-center gap-2.5 rounded-md border border-border bg-muted/50 px-3 py-2.5 text-sm">
      <span className="relative flex h-2 w-2">
        {connected && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-60" />
        )}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${connected ? 'bg-success' : 'bg-warning'}`} />
      </span>
      <span className="font-medium text-muted-foreground">{connected ? 'Connected' : 'Connecting…'}</span>
    </div>
  );
}
