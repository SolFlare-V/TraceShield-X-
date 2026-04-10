#!/bin/bash
echo "Starting TraceShield X++ backend..."
cd backend
uvicorn main:app --reload --port 8000 &
echo "Starting frontend..."
cd ../frontend
npm run dev
