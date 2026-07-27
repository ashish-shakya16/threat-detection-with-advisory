# SecureX API Documentation

## Base URL
```
http://localhost:5000/api
```

## Endpoints

### Threats

#### GET /threats/
Get all threats with optional filtering.

**Query Parameters:**
- `limit` (int): Maximum threats to return (default: 50)
- `hours` (int): Time window in hours (default: 24)
- `risk_level` (string): Filter by risk level (Low, Medium, High, Critical)

**Response:**
```json
{
  "success": true,
  "count": 5,
  "data": [...]
}
```

#### GET /threats/{id}
Get detailed threat information.

#### PUT /threats/{id}/status
Update threat status (resolved, ignored, escalated).

#### GET /threats/critical
Get only critical threats.

### Statistics

#### GET /stats/
Get overall threat statistics.

#### GET /stats/by-category
Get statistics grouped by category.

#### GET /stats/by-severity
Get statistics grouped by severity.

### Analytics

#### GET /analytics/timeline
Get threat detection timeline (default 7 days).

#### GET /analytics/top-threats
Get most frequently detected threats.

#### GET /analytics/detection-rate
Get detection rate statistics by period (daily, weekly, monthly).
