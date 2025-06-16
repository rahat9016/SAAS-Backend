# 🛒 SaaS eCommerce Platform

A scalable multi-tenant eCommerce SaaS application built using **Python**, **Django**, **Django REST Framework (DRF)**, and **PostgreSQL**. This platform enables businesses to create and manage their own online stores within a shared infrastructure.

---

## 🚀 Features

### ✅ Multi-Tenant Support
- Store-level data isolation (row-level or schema-based).
- Each vendor gets their own dashboard and storefront.

### ✅ Product Management
- CRUD for products, categories, brands, tags.
- Support for product variants (size, color).
- Image upload via Cloudinary or local storage.

### ✅ Order & Checkout
- Shopping cart with persistent session.
- Order placement, history, and tracking.
- Coupon, discount, and tax support.

### ✅ Payment Integration
- Integrated with Stripe/PayPal.
- Secure transaction handling.

### ✅ User Management
- Vendor and customer registration/login.
- Role-based access: Super Admin, Vendor, Customer.
- JWT Authentication via DRF Simple JWT.

### ✅ Admin Panel
- Django admin extended for superuser control.
- Vendor-specific dashboards for store performance.

### ✅ Analytics & Reports
- Sales statistics and order analytics per store.
- Exportable reports (CSV, PDF support optional).

### ✅ API-First Architecture
- Full REST API with DRF.
- OpenAPI/Swagger documentation included.

---

## 🛠 Tech Stack

| Layer         | Technology                  |
|---------------|-----------------------------|
| Backend       | Python, Django, DRF         |
| Database      | PostgreSQL                  |
| Auth          | JWT (DRF Simple JWT)        |
| Media Upload  | Cloudinary or local files   |
| API Docs      | Swagger/OpenAPI             |
| Deployment    | Docker, Heroku/AWS/DigitalOcean |

---

## 🧪 Local Development

### ✅ Prerequisites

- Python 3.10+
- PostgreSQL
- pip / poetry
- virtualenv (optional)
- Docker (optional but recommended)

---

### 🔧 Setup

```bash
# Create requirements.txt
pip freeze > requirements.txt

# Clone the repository
git clone https://github.com/rahat9016/SAAS-Backend
cd SAAS-Backend

# Create a virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
