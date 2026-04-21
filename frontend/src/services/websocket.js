// frontend/src/services/websocket.js
class WebSocketService {
  constructor() {
    this.socket = null;
    this.handlers = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectDelay = 1000;
    this.isConnecting = false;
    this.url = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';
    this.messageQueue = [];
    this.connected = false;
  }

  connect() {
    if (this.socket?.readyState === WebSocket.OPEN || this.isConnecting) {
      return;
    }

    this.isConnecting = true;

    try {
      this.socket = new WebSocket(this.url);

      this.socket.onopen = () => {
        console.log('WebSocket connected');
        this.isConnecting = false;
        this.connected = true;
        this.reconnectAttempts = 0;
        
        // Send queued messages
        while (this.messageQueue.length) {
          this.send(this.messageQueue.shift());
        }
        
        this.notifyHandlers('connect', { 
          type: 'status', 
          data: { status: 'connected' }, 
          timestamp: new Date().toISOString() 
        });
      };

      this.socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.notifyHandlers(message.type, message);
          
          // Also notify wildcard handlers
          this.notifyHandlers('*', message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      this.socket.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason);
        this.isConnecting = false;
        this.connected = false;
        this.socket = null;
        
        if (!event.wasClean && this.reconnectAttempts < this.maxReconnectAttempts) {
          setTimeout(() => {
            this.reconnectAttempts++;
            this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, 30000);
            console.log(`Reconnecting... Attempt ${this.reconnectAttempts}`);
            this.connect();
          }, this.reconnectDelay);
        }
      };

      this.socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.isConnecting = false;
      };
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      this.isConnecting = false;
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.handlers.clear();
    this.connected = false;
  }

  subscribe(type, handler) {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, []);
    }
    this.handlers.get(type).push(handler);

    // Auto-connect if not connected
    if (!this.connected && (!this.socket || this.socket.readyState !== WebSocket.OPEN)) {
      this.connect();
    }
  }

  unsubscribe(type, handler) {
    const handlers = this.handlers.get(type);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  send(message) {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket not connected, queuing message');
      this.messageQueue.push(message);
      this.connect();
    }
  }

  subscribeToThreats(handler) {
    this.subscribe('threat', (message) => {
      handler(message.data);
    });
  }

  subscribeToMetrics(handler) {
    this.subscribe('metric', (message) => {
      handler(message.data);
    });
  }

  subscribeToAlerts(handler) {
    this.subscribe('alert', (message) => {
      handler(message.data);
    });
  }

  subscribeToDefenseActions(handler) {
    this.subscribe('defense_action', (message) => {
      handler(message.data);
    });
  }

  subscribeToBlockchainEvents(handler) {
    this.subscribe('blockchain', (message) => {
      handler(message.data);
    });
  }

  isConnected() {
    return this.connected && this.socket?.readyState === WebSocket.OPEN;
  }

  notifyHandlers(type, message) {
    const handlers = this.handlers.get(type);
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler(message);
        } catch (e) {
          console.error(`Handler error for ${type}:`, e);
        }
      });
    }
  }
}

export const webSocketService = new WebSocketService();