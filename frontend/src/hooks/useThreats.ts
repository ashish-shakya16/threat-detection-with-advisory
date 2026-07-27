import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useThreats(hours: number) {
  return useQuery({
    queryKey: ['threats', { hours, limit: 100 }],
    queryFn: () => api.threats.list({ hours, limit: 100 }),
  });
}
