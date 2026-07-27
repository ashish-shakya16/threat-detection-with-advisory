import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useSystemMetrics() {
  return useQuery({
    queryKey: ['system-metrics'],
    queryFn: api.systemMetrics.get,
    refetchInterval: 5000,
  });
}
