#!/bin/bash
# ============================================================
# STEP 4: Build frontend and serve with nginx
# ============================================================

set -e
PROJECT_DIR="$HOME/threatshield-project"

# ── Build React frontend ──────────────────────────────────────
echo "Building React frontend..."
cd "$PROJECT_DIR/frontend"

# Point API to the Azure VM (localhost since both on same VM)
cat > .env.production << 'FRONTENVEOF'
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
FRONTENVEOF

npm install
npm run build

echo "Frontend built successfully"

# ── Install and configure nginx ──────────────────────────────
echo "Setting up nginx..."
sudo apt-get install -y nginx

sudo tee /etc/nginx/sites-available/threatshield << 'NGINXEOF'
server {
    listen 80;
    server_name _;

    # Frontend (React build)
    root /home/azureuser/threatshield-project/frontend/build;
    index index.html;

    # Handle React Router (SPA)
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Backend API proxy
    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 120s;
    }

    # WebSocket proxy
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
NGINXEOF

sudo ln -sf /etc/nginx/sites-available/threatshield /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx

echo ""
echo "✅ Frontend served by nginx on port 80"
echo "✅ Open browser: http://$(curl -s ifconfig.me)"
