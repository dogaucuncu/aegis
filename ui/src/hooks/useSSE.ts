import { useEffect, useRef } from "react";

// Bir SSE (EventSource) bağlantısı açar ve "alert" olaylarında callback'i çağırır.
export function useSSE(url: string, eventName: string, onMessage: (data: unknown) => void) {
  const cbRef = useRef(onMessage);
  cbRef.current = onMessage;

  useEffect(() => {
    const es = new EventSource(url);
    const handler = (e: MessageEvent) => {
      try {
        cbRef.current(JSON.parse(e.data));
      } catch {
        /* yoksay */
      }
    };
    es.addEventListener(eventName, handler as EventListener);
    return () => es.close();
  }, [url, eventName]);
}
