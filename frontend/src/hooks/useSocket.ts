import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { socket } from '@/lib/socket';

export function useSocket() {
  const queryClient = useQueryClient();

  useEffect(() => {
    socket.connect();

    function handleNewThreats(data: { count: number }) {
      toast('New threats detected', {
        description: `${data.count} new threat(s) found`,
      });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['threats'] });
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
    }

    function handleSystemMetrics(data: unknown) {
      queryClient.setQueryData(['system-metrics-live'], data);
    }

    socket.on('new_threats', handleNewThreats);
    socket.on('system_metrics', handleSystemMetrics);

    return () => {
      socket.off('new_threats', handleNewThreats);
      socket.off('system_metrics', handleSystemMetrics);
      socket.disconnect();
    };
  }, [queryClient]);
}
