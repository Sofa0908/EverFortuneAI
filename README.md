# EverFortuneAI
Answer for written interview.

scraper.py - A script that scrapes and records this data into the database every minute. (the every minute part will be accomplished by having a crontab script to call it every minute, or after deployment on lambda and have CloudFront set up a trigger to call it every minute)

restful_api.py - The main body of my RESTful API providing the required function for this task.

model.py - model & schema declaration for SQLAlchemy and Marshmallow
