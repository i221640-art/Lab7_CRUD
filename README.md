# Flask TODO sample
Run locally:
1. python -m venv venv && source venv/bin/activate  # (or venv\Scripts\activate on Windows)
2. pip install -r requirements.txt
3. python app.py
API:
GET /todos
POST /todos  { "title": "Buy milk" }
PUT /todos/{id}
DELETE /todos/{id}
