"""
Scheduled job to automatically populate daily vulnerability summaries.
This service runs daily to calculate and store vulnerability counts for the previous day.
"""
import schedule
import time
import threading
from datetime import date, timedelta
from services.daily_summary_service import DailySummaryService
import logging

logger = logging.getLogger(__name__)

def run_daily_summary_job():
    """Run the daily summary calculation job"""
    session = None
    try:
        logger.info("Starting daily vulnerability summary job...")
        
        # Calculate summary for yesterday (to ensure all scans are complete)
        yesterday = date.today() - timedelta(days=1)
        
        # Get a new session for this job
        session = DailySummaryService.get_session()
        
        # Calculate the summary
        summary = DailySummaryService.calculate_daily_summary(session, yesterday)
        
        if summary:
            logger.info(f"✅ Daily summary calculated for {yesterday}: "
                       f"Critical={summary.critical_count}, "
                       f"High={summary.high_count}, "
                       f"Medium={summary.medium_count}, "
                       f"Low={summary.low_count}")
        else:
            logger.warning(f"No data found for {yesterday}")
            
    except Exception as e:
        logger.error(f"❌ Error in daily summary job: {e}")
    finally:
        if session:
            session.close()

def run_weekly_cleanup():
    """Run weekly cleanup of old summaries"""
    try:
        logger.info("Starting weekly cleanup of old daily summaries...")
        
        # Keep summaries for 1 year
        deleted_count = DailySummaryService.cleanup_old_summaries(days_to_keep=365)
        
        logger.info(f"✅ Cleaned up {deleted_count} old daily summaries")
        
    except Exception as e:
        logger.error(f"❌ Error in weekly cleanup job: {e}")

def start_daily_summary_scheduler():
    """Start the daily summary scheduler"""
    try:
        # Schedule daily summary calculation at 2 AM every day
        schedule.every().day.at("02:00").do(run_daily_summary_job)
        
        # Schedule weekly cleanup on Sundays at 3 AM
        schedule.every().sunday.at("03:00").do(run_weekly_cleanup)
        
        logger.info("Daily summary scheduler started")
        logger.info("- Daily summary calculation: 2:00 AM daily")
        logger.info("- Weekly cleanup: 3:00 AM on Sundays")
        
        # Run the scheduler in a separate thread
        def scheduler_loop():
            logger.info("Daily summary scheduler loop started")
            while True:
                try:
                    schedule.run_pending()
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    logger.error(f"Error in scheduler loop: {e}")
                    time.sleep(60)  # Wait before retrying
        
        scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
        scheduler_thread.start()
        
        logger.info("Daily summary scheduler thread started successfully")
        return scheduler_thread
        
    except Exception as e:
        logger.error(f"❌ Error starting daily summary scheduler: {e}")
        return None

def run_immediate_backfill(days_back: int = 7):
    """Run immediate backfill for the last N days"""
    try:
        logger.info(f"Running immediate backfill for last {days_back} days...")
        
        count = DailySummaryService.backfill_historical_data(days_back)
        logger.info(f"✅ Immediate backfill completed: {count} summaries created/updated")
        
        return count
        
    except Exception as e:
        logger.error(f"❌ Error in immediate backfill: {e}")
        return 0

if __name__ == "__main__":
    # For testing purposes
    import argparse
    
    parser = argparse.ArgumentParser(description="Daily Summary Scheduler")
    parser.add_argument("--backfill", type=int, metavar="DAYS", 
                       help="Run immediate backfill for specified number of days")
    parser.add_argument("--start-scheduler", action="store_true", 
                       help="Start the scheduler")
    parser.add_argument("--run-job", action="store_true", 
                       help="Run the daily summary job immediately")
    
    args = parser.parse_args()
    
    if args.backfill:
        run_immediate_backfill(args.backfill)
    elif args.start_scheduler:
        start_daily_summary_scheduler()
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Scheduler stopped")
    elif args.run_job:
        run_daily_summary_job()
    else:
        print("Use --help to see available options")
