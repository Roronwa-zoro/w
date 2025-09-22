# Flask Web Application

A comprehensive Flask web application with user authentication, patient management system, and activity logging.

## Features

- **User Authentication**: Login and logout functionality
- **User Registration**: Register new viewer accounts only
- **Patient Management**: Complete CRUD operations for patient records
- **Admin Controls**: Admin-only access to add, edit, and delete patients
- **Activity Logging**: Track all changes with timestamps and user information
- **Dashboard**: User-specific dashboard with patient data and activity logs
- **Database**: SQLite3 database with users, patients, and logs tables
- **Security**: Password hashing, session management, and role-based access
- **Admin Account**: Pre-configured admin user (mounir/3mmk)

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open your browser and navigate to `http://localhost:5000`

## Default Admin Account

- **Username**: mounir
- **Password**: 3mmk
- **Account Type**: admin

## Account Types

- **Admin**: Full access (currently only the default admin account)
- **Viewer**: Limited access (can be created through registration)

## Database

The application uses SQLite3 with three main tables:

### Users Table
- `id`: Primary key
- `username`: Unique username
- `password`: Hashed password
- `account_type`: Either 'admin' or 'viewer'

### Patients Table
- `id`: Primary key
- `full_name`: Patient's full name
- `age`: Patient's age
- `diagnosis`: Medical diagnosis
- `entry_date`: Date of entry
- `status`: Current status (Active, Pending, Discharged)
- `doctor_name`: Assigned doctor
- `is_in_surgery_section`: Boolean flag for surgery section
- `is_prepared`: Boolean flag for preparation status
- `created_at`: Record creation timestamp
- `updated_at`: Last update timestamp

### Logs Table
- `id`: Primary key
- `user_id`: Foreign key to users table
- `action`: Action performed (CREATE, UPDATE, DELETE)
- `table_name`: Table that was modified
- `record_id`: ID of the modified record
- `old_values`: Previous values (for updates/deletes)
- `new_values`: New values (for creates/updates)
- `timestamp`: When the action occurred

## Security Features

- Passwords are hashed using SHA-256
- Session management for user authentication
- Input validation and error handling
- CSRF protection through Flask's built-in features

## Usage

### For Admins
1. **Login**: Use admin credentials (mounir/3mmk) to access full functionality
2. **Add Patients**: Click "Add New Patient" to create new patient records
3. **Edit Patients**: Click "Edit" button on any patient row to modify information
4. **Delete Patients**: Click "Delete" button to remove patient records
5. **View Logs**: Monitor all activity in the Recent Activity Logs section

### For Viewers
1. **Login**: Use viewer account credentials to access the dashboard
2. **View Patients**: Browse the patients table (read-only access)
3. **View Logs**: See recent activity logs
4. **Register**: Create new viewer accounts through registration

### General
- **Dashboard**: View user information, patient data, and activity logs
- **Logout**: End the current session

## File Structure

```
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── users.db           # SQLite database (created automatically)
└── templates/         # HTML templates
    ├── base.html      # Base template
    ├── index.html     # Dashboard page
    ├── login.html     # Login page
    └── register.html  # Registration page
```
