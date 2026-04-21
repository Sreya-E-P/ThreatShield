// frontend/src/hooks/useWebSocket.js
import { useEffect, useState, useCallback, useRef } from 'react';
import { webSocketService } from '../services/websocket';

export const useWebSocket = (topics = []) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(null);
  const [messages, setMessages] = useState([]);
  const handlersRef = useRef(new Map());

  useEffect(() => {
    const handleConnect = () => {
      setIsConnected(true);
    };

    const handleDisconnect = () => {
      setIsConnected(false);
    };

    const handleMessage = (message) => {
      setLastMessage(message);
      setMessages(prev => [...prev.slice(-100), message]);
    };

    webSocketService.subscribe('connect', handleConnect);
    webSocketService.subscribe('disconnect', handleDisconnect);
    webSocketService.subscribe('*', handleMessage);

    topics.forEach(topic => {
      webSocketService.subscribe(topic, handleMessage);
    });

    webSocketService.connect();

    return () => {
      webSocketService.unsubscribe('connect', handleConnect);
      webSocketService.unsubscribe('disconnect', handleDisconnect);
      webSocketService.unsubscribe('*', handleMessage);
      topics.forEach(topic => {
        webSocketService.unsubscribe(topic, handleMessage);
      });
    };
  }, [topics]);

  const sendMessage = useCallback((message) => {
    webSocketService.send(message);
  }, []);

  const subscribe = useCallback((topic, handler) => {
    handlersRef.current.set(topic, handler);
    webSocketService.subscribe(topic, handler);
  }, []);

  const unsubscribe = useCallback((topic) => {
    const handler = handlersRef.current.get(topic);
    if (handler) {
      webSocketService.unsubscribe(topic, handler);
      handlersRef.current.delete(topic);
    }
  }, []);

  return {
    isConnected,
    lastMessage,
    messages,
    sendMessage,
    subscribe,
    unsubscribe,
  };
};