#!/bin/sh

echo '🚀 Starting Django Application...'
echo '----------------------------------------'

echo '📊 Step 1/4: Checking Database...'
while ! nc -z $DB_HOSTNAME $DB_POST; then
    echo '❌ ERROR: Cannot connect to database!'
    echo '   Please check:'
    echo '   - Is PostgreSQL running?'
    echo '   - Are DB_HOSTNAME and DB_PORT correct?'
    exit 1
fi

echo '✅ Database connection successful!'
python manage.py migrate
python manage.py collectstatic --no-input

echo '🎉 Application ready!'t