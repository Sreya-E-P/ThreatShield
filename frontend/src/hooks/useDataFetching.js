import { useState, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';

export const useDataFetching = (queryKey, fetchFn, options = {}) => {
  const { enabled = true, retry = 3, staleTime = 30000, cacheTime = 5 * 60 * 1000, onSuccess, onError, showErrorToast = true, refetchInterval = null, initialData = null } = options;
  const queryClient = useQueryClient();
  const [isFetching, setIsFetching] = useState(false);

  const { data, isLoading, error, refetch, isRefetching } = useQuery({
    queryKey: Array.isArray(queryKey) ? queryKey : [queryKey],
    queryFn: async () => {
      setIsFetching(true);
      try {
        const result = await fetchFn();
        setIsFetching(false);
        onSuccess?.(result);
        return result;
      } catch (err) {
        setIsFetching(false);
        if (showErrorToast) toast.error(`Failed to fetch data: ${err.message}`);
        onError?.(err);
        throw err;
      }
    },
    enabled, retry, staleTime, cacheTime, refetchInterval, initialData, placeholderData: initialData,
  });

  const refresh = useCallback(async () => { setIsFetching(true); const result = await refetch(); setIsFetching(false); return result.data; }, [refetch]);
  const invalidate = useCallback(() => queryClient.invalidateQueries({ queryKey: [queryKey] }), [queryClient, queryKey]);
  const prefetch = useCallback(() => queryClient.prefetchQuery({ queryKey: [queryKey], queryFn: fetchFn }), [queryClient, queryKey, fetchFn]);

  return { data, isLoading, isFetching, isRefetching, error, refetch: refresh, invalidate, prefetch };
};

export const useWebSocketData = (topic, handler) => {
  const [data, setData] = useState(null);
  const handlerRef = React.useRef(handler);
  React.useEffect(() => { handlerRef.current = handler; }, [handler]);
  React.useEffect(() => {
    const ws = new WebSocket(`${process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws'}`);
    ws.onopen = () => ws.send(JSON.stringify({ type: 'subscribe', topic }));
    ws.onmessage = (event) => { try { const message = JSON.parse(event.data); setData(message); handlerRef.current?.(message); } catch (err) { console.error('WebSocket error:', err); } };
    ws.onerror = (error) => console.error('WebSocket error:', error);
    return () => ws.close();
  }, [topic]);
  return data;
};