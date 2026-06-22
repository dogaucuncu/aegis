import { useEffect, useRef } from "react";

// Opens an SSE (EventSource) connection and calls the callback on "alert" events.
export function useSSE(url: string, eventName: string, onMessage: (data: unknown) => void) {
  const cbRef = useRef(onMessage);
  cbRef.current = onMessage;

  useEffect(() => {
    const es = new EventSource(url);
    const handler = (e: MessageEvent) => {
      try {
        cbRef.current(JSON.parse(e.data));
      } catch {
        /* ignore */
      }
    };
    es.addEventListener(eventName, handler as EventListener);
    return () => es.close();
  }, [url, eventName]);
}
