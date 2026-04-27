# Auto-install dependencies
import subprocess
import sys

def install_package(package):
    """Install a package using pip with better feedback"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else 'Unknown error'
            print(f"    Error: {error_msg}")
            return False
        return True
    except Exception as e:
        print(f"    Error: {str(e)}")
        return False

def check_and_install_dependencies():
    """Check and install required packages with improved feedback"""
    required_packages = ['pandas', 'openpyxl', 'pytz']
    missing_packages = []
    
    print("Checking dependencies...")
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✓ {package} is installed")
        except ImportError:
            print(f"  ✗ {package} is missing")
            missing_packages.append(package)
    
    if missing_packages:
        print("\nInstalling missing dependencies...")
        failed_packages = []
        for package in missing_packages:
            print(f"  - Installing {package}...", end=" ")
            if install_package(package):
                print("✓ Success")
            else:
                print("✗ Failed")
                failed_packages.append(package)
        
        if failed_packages:
            print(f"\nFailed to install the following packages: {', '.join(failed_packages)}")
            print("Please install them manually using:")
            for package in failed_packages:
                print(f"  pip install {package}")
            sys.exit(1)
        
        print("\nAll dependencies installed successfully!")
    print()

check_and_install_dependencies()

import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import pytz
import json
import argparse
import os
import platform
from openpyxl.styles import Alignment
from urllib.parse import unquote

# ============== CONSTANTS ==============

# Timezone
ISRAEL_TIMEZONE = 'Asia/Jerusalem'

# Epoch dates
CHROME_EPOCH = datetime(1601, 1, 1)
UNIX_EPOCH = datetime(1970, 1, 1)

# Output file names
OUTPUT_HISTORY = 'Browser_History.xlsx'
OUTPUT_DOWNLOADS = 'Browser_Downloads.xlsx'
OUTPUT_BOOKMARKS = 'Browser_Bookmarks.xlsx'

# Microseconds to seconds conversion
MICROSECONDS_TO_SECONDS = 1000000

# Bytes to MB conversion
BYTES_TO_MB = 1024 * 1024

# Chrome/Edge transition types
TRANSITION_TYPES = {
    0: 'Link', 
    1: 'Typed', 
    2: 'Bookmark', 
    3: 'Auto Subframe',
    4: 'Manual Subframe', 
    5: 'Generated', 
    6: 'Auto Toplevel',
    7: 'Form Submit', 
    8: 'Reload', 
    9: 'Keyword', 
    10: 'Keyword Generated'
}

# Firefox visit types
FIREFOX_VISIT_TYPES = {
    1: 'Link', 
    2: 'Typed', 
    3: 'Bookmark', 
    4: 'Embed',
    5: 'Redirect Permanent', 
    6: 'Redirect Temporary',
    7: 'Download', 
    8: 'Framed Link', 
    9: 'Reload'
}

# Download states
DOWNLOAD_STATES = {
    0: 'In Progress', 
    1: 'Complete', 
    2: 'Cancelled', 
    3: 'Interrupted', 
    4: 'Interrupted'
}

# Download interrupt reasons
INTERRUPT_REASONS = {
    0: 'No Interruption', 
    1: 'File Error', 
    2: 'Access Denied', 
    3: 'Disk Full',
    5: 'Path Too Long', 
    6: 'File Too Large', 
    7: 'Virus Detected', 
    10: 'Temporary Problem',
    11: 'Blocked', 
    12: 'Security Check Failed', 
    13: 'Resume Error', 
    20: 'Network Failed',
    21: 'Network Timeout', 
    22: 'Network Disconnected', 
    23: 'Server Failed',
    30: 'Server Unauthorized', 
    31: 'Server Certificate Problem', 
    32: 'Server Forbidden',
    33: 'Server Unreachable', 
    34: 'Content Length Mismatch', 
    40: 'Cancelled by User',
    41: 'Browser Shutdown'
}

# Danger types
DANGER_TYPES = {
    0: 'Safe', 
    1: 'Dangerous File', 
    2: 'Dangerous URL', 
    3: 'Dangerous Content',
    4: 'Uncommon Content', 
    5: 'Uncommon Content', 
    6: 'User Validated',
    7: 'Dangerous Host', 
    8: 'Potentially Unwanted', 
    9: 'Whitelisted by Policy',
    10: 'Pending Scan', 
    11: 'Blocked - Password Protected', 
    12: 'Blocked - Too Large',
    13: 'Sensitive Content Warning', 
    14: 'Blocked - Sensitive Content',
    15: 'Deep Scanned - Safe', 
    16: 'Deep Scanned - Dangerous',
    17: 'Prompt for Scanning', 
    18: 'Account Compromise Risk'
}

# Firefox download states
FIREFOX_DOWNLOAD_STATES = {
    0: 'In Progress',
    1: 'Complete',
    2: 'Failed',
    3: 'Cancelled',
    4: 'Paused',
    5: 'Queued',
    6: 'Blocked Parental',
    7: 'Dirty',
    8: 'Blocked Policy'
}

# Firefox bookmark types
FIREFOX_BOOKMARK_TYPES = {
    1: 'Bookmark',
    2: 'Folder',
    3: 'Separator'
}

# ============== UTILITY FUNCTIONS ==============

def chrome_time_to_datetime(chrome_time):
    """Convert Chrome timestamp to datetime in Israeli timezone"""
    if pd.notna(chrome_time) and chrome_time:
        try:
            utc_time = CHROME_EPOCH + timedelta(microseconds=int(chrome_time))
            utc_time = pytz.utc.localize(utc_time)
            israel_tz = pytz.timezone(ISRAEL_TIMEZONE)
            return utc_time.astimezone(israel_tz).replace(tzinfo=None)
        except (ValueError, OverflowError):
            return None
    return None

def firefox_time_to_datetime(firefox_time):
    """Convert Firefox timestamp (microseconds) to datetime in Israeli timezone"""
    if pd.notna(firefox_time) and firefox_time:
        try:
            utc_time = UNIX_EPOCH + timedelta(microseconds=int(firefox_time))
            utc_time = pytz.utc.localize(utc_time)
            israel_tz = pytz.timezone(ISRAEL_TIMEZONE)
            return utc_time.astimezone(israel_tz).replace(tzinfo=None)
        except (ValueError, OverflowError):
            return None
    return None

def firefox_time_ms_to_datetime(firefox_time_ms):
    """Convert Firefox timestamp (milliseconds) to datetime in Israeli timezone"""
    if pd.notna(firefox_time_ms) and firefox_time_ms:
        try:
            utc_time = UNIX_EPOCH + timedelta(milliseconds=int(firefox_time_ms))
            utc_time = pytz.utc.localize(utc_time)
            israel_tz = pytz.timezone(ISRAEL_TIMEZONE)
            return utc_time.astimezone(israel_tz).replace(tzinfo=None)
        except (ValueError, OverflowError):
            return None
    return None

def detect_browser_type(cursor):
    """Detect browser type based on database structure and content"""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    if 'urls' in tables:
        # Check for Chrome or Edge specific URLs
        cursor.execute("SELECT url FROM urls WHERE url LIKE 'chrome://%' LIMIT 1")
        chrome_url = cursor.fetchone()
        
        cursor.execute("SELECT url FROM urls WHERE url LIKE 'edge://%' LIMIT 1")
        edge_url = cursor.fetchone()
        
        if chrome_url and not edge_url:
            return 'Chrome'
        elif edge_url and not chrome_url:
            return 'Edge'
        else:
            return 'Chrome/Edge'
    elif 'moz_places' in tables:
        return 'Firefox'
    return 'Unknown'

def decode_transition(transition):
    """Decode Chrome/Edge transition type to readable text"""
    if pd.isna(transition):
        return None
    base_type = int(transition) & 0xFF
    return TRANSITION_TYPES.get(base_type, f'Unknown ({base_type})')

def decode_firefox_visit_type(visit_type):
    """Decode Firefox visit type to readable text"""
    if pd.isna(visit_type):
        return None
    visit_type_int = int(visit_type)
    return FIREFOX_VISIT_TYPES.get(visit_type_int, f'Unknown ({visit_type_int})')

def decode_download_state(state):
    """Decode download state to readable text"""
    if pd.isna(state):
        return None
    state_int = int(state)
    return DOWNLOAD_STATES.get(state_int, f'Unknown ({state_int})')

def decode_firefox_download_state(state):
    """Decode Firefox download state to readable text"""
    if pd.isna(state):
        return None
    state_int = int(state)
    return FIREFOX_DOWNLOAD_STATES.get(state_int, f'Unknown ({state_int})')

def decode_interrupt_reason(reason):
    """Decode download interrupt reason to readable text"""
    if pd.isna(reason):
        return None
    reason_int = int(reason)
    return INTERRUPT_REASONS.get(reason_int, f'Unknown ({reason_int})')

def decode_opened(opened):
    """Decode opened status to readable text"""
    if pd.isna(opened):
        return None
    return 'Yes' if int(opened) == 1 else 'No'

def decode_danger_type(danger):
    """Decode danger type to readable security status"""
    if pd.isna(danger):
        return None
    danger_int = int(danger)
    return DANGER_TYPES.get(danger_int, f'Unknown ({danger_int})')

def decode_firefox_bookmark_type(bm_type):
    """Decode Firefox bookmark type to readable text"""
    if pd.isna(bm_type):
        return None
    bm_type_int = int(bm_type)
    return FIREFOX_BOOKMARK_TYPES.get(bm_type_int, f'Unknown ({bm_type_int})')

def clean_file_uri(uri):
    """Convert file:// URI to readable path"""
    if pd.isna(uri) or not uri:
        return None
    if uri.startswith('file:///'):
        path = unquote(uri[8:])
        return path
    return uri

def open_file(filepath):
    """Open file with default application"""
    try:
        filepath = str(Path(filepath).absolute())
        if platform.system() == 'Windows':
            os.startfile(filepath)
        elif platform.system() == 'Darwin':  # macOS
            subprocess.run(['open', filepath], check=True)
        else:  # Linux
            subprocess.run(['xdg-open', filepath], check=True)
        return True
    except Exception as e:
        print(f"  Could not open file automatically: {e}")
        return False

def parse_date(date_str):
    """Parse date string in YYYY-MM-DD format"""
    try:
        return datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        return None

def filter_by_date_range(df, date_column, start_date, end_date):
    """Filter DataFrame by date range"""
    if df is None or df.empty:
        return df
    
    if date_column not in df.columns:
        return df
    
    # Create a copy to avoid modifying original
    df = df.copy()
    
    # Convert column to datetime if needed, handling None values
    df[date_column] = pd.to_datetime(df[date_column], errors='coerce')
    
    mask = pd.Series([True] * len(df), index=df.index)
    
    if start_date:
        start_dt = pd.Timestamp(start_date)
        mask &= (df[date_column] >= start_dt) | (df[date_column].isna())
        mask &= df[date_column].notna()  # Exclude NaT values when filtering
    
    if end_date:
        end_dt = pd.Timestamp(end_date) + timedelta(days=1)
        mask &= (df[date_column] < end_dt) | (df[date_column].isna())
        mask &= df[date_column].notna()
    
    return df[mask]

def parse_arguments():
    """Parse command line arguments for date filtering"""
    parser = argparse.ArgumentParser(
        description='Browser History Analyzer - Extract and analyze browser history, downloads, and bookmarks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python History.py
  python History.py --start 2024-01-01
  python History.py --end 2024-06-30
  python History.py --start 2024-01-01 --end 2024-06-30
  python History.py --start 2024-01-01 --no-open
        '''
    )
    
    parser.add_argument(
        '--start',
        type=str,
        help='Start date for filtering (YYYY-MM-DD format)',
        metavar='DATE'
    )
    
    parser.add_argument(
        '--end',
        type=str,
        help='End date for filtering (YYYY-MM-DD format)',
        metavar='DATE'
    )
    
    parser.add_argument(
        '--no-open',
        action='store_true',
        help='Do not automatically open the output file'
    )
    
    args = parser.parse_args()
    
    # Parse dates
    start_date = None
    end_date = None
    
    if args.start:
        start_date = parse_date(args.start)
        if start_date is None:
            print(f"Invalid start date format: {args.start}")
            print("Please use YYYY-MM-DD format (e.g., 2024-01-15)")
            sys.exit(1)
    
    if args.end:
        end_date = parse_date(args.end)
        if end_date is None:
            print(f"Invalid end date format: {args.end}")
            print("Please use YYYY-MM-DD format (e.g., 2024-12-31)")
            sys.exit(1)
    
    if start_date and end_date and start_date > end_date:
        print("Error: Start date must be before end date")
        sys.exit(1)
    
    return start_date, end_date, args.no_open

# ============== HISTORY FUNCTIONS ==============

def get_user_choice():
    """Prompt user to choose betweecn full history, download history, or bookmarks"""
    print("\nSelect an option:")
    print("1. View Full Browsing History")
    print("2. View Download History Only")
    print("3. View Bookmarks")
    
    while True:
        choice = input("\nEnter your choice (1, 2, or 3): ").strip()
        if choice in ['1', '2', '3']:
            return int(choice)
        print("Invalid choice. Please enter 1, 2, or 3.")

def read_history_file(file_path):
    """Read browser history from SQLite file"""
    conn = sqlite3.connect(file_path)
    cursor = conn.cursor()
    
    browser_type = detect_browser_type(cursor)
    
    if browser_type == 'Unknown':
        conn.close()
        return None, browser_type
    
    if browser_type in ['Chrome', 'Edge', 'Chrome/Edge']:
        cursor.execute("""
            SELECT urls.*, visits.visit_time, visits.visit_duration, visits.transition,
                   referrer_urls.url as referrer_url
            FROM urls 
            LEFT JOIN visits ON urls.id = visits.url
            LEFT JOIN visits as referrer_visits ON visits.from_visit = referrer_visits.id
            LEFT JOIN urls as referrer_urls ON referrer_visits.url = referrer_urls.id
        """)
        rows = cursor.fetchall()
        
        cursor.execute("PRAGMA table_info(urls)")
        url_columns = [col[1] for col in cursor.fetchall()]
        all_columns = url_columns + ['visit_time', 'visit_duration', 'transition', 'referrer_url']
        
        df = pd.DataFrame(rows, columns=all_columns)
        
        for col in ['last_visit_time', 'visit_time']:
            if col in df.columns:
                df[col] = df[col].apply(chrome_time_to_datetime)
        
        if 'visit_duration' in df.columns:
            df['visit_duration'] = df['visit_duration'] / MICROSECONDS_TO_SECONDS
        
        if 'transition' in df.columns:
            df['transition'] = df['transition'].apply(decode_transition)
        
        if 'hidden' in df.columns:
            df['hidden'] = df['hidden'].apply(decode_opened)
        
        priority_cols = ['id', 'url', 'title', 'visit_time', 'last_visit_time', 'transition', 
                         'referrer_url', 'visit_count', 'typed_count']
        other_cols = [col for col in df.columns if col not in priority_cols]
        column_order = [col for col in priority_cols if col in df.columns] + other_cols
        df = df[column_order]
        
        if 'visit_time' in df.columns:
            df = df.sort_values('visit_time', ascending=False)
        elif 'last_visit_time' in df.columns:
            df = df.sort_values('last_visit_time', ascending=False)
    
    elif browser_type == 'Firefox':
        cursor.execute("""
            SELECT moz_places.url, moz_places.title, moz_places.visit_count, moz_places.typed, 
                   moz_places.frecency, moz_historyvisits.visit_date, moz_historyvisits.visit_type,
                   referrer_places.url as referrer_url
            FROM moz_places
            LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
            LEFT JOIN moz_historyvisits as referrer_visits ON moz_historyvisits.from_visit = referrer_visits.id
            LEFT JOIN moz_places as referrer_places ON referrer_visits.place_id = referrer_places.id
        """)
        rows = cursor.fetchall()
        
        df = pd.DataFrame(rows, columns=['url', 'title', 'visit_count', 'typed', 'frecency', 
                                          'visit_date', 'visit_type', 'referrer_url'])
        df['visit_date'] = df['visit_date'].apply(firefox_time_to_datetime)
        
        if 'visit_type' in df.columns:
            df['visit_type'] = df['visit_type'].apply(decode_firefox_visit_type)
        
        if 'typed' in df.columns:
            df['typed'] = df['typed'].apply(decode_opened)
        
        df = df.sort_values('visit_date', ascending=False)
    
    conn.close()
    return df, browser_type

# ============== DOWNLOAD FUNCTIONS ==============

def read_firefox_downloads(cursor):
    """Read Firefox download history from moz_annos and moz_places tables"""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_annos'")
    has_annos = cursor.fetchone() is not None
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_anno_attributes'")
    has_anno_attrs = cursor.fetchone() is not None
    
    if not has_annos or not has_anno_attrs:
        return None
    
    cursor.execute("""
        SELECT 
            p.id,
            p.url as source_url,
            p.title,
            aa.name as anno_name,
            a.content,
            a.dateAdded,
            a.lastModified
        FROM moz_annos a
        JOIN moz_places p ON a.place_id = p.id
        JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
        WHERE aa.name IN ('downloads/destinationFileURI', 'downloads/metaData')
        ORDER BY p.id, aa.name
    """)
    rows = cursor.fetchall()
    
    if not rows:
        return None
    
    downloads = {}
    for row in rows:
        place_id, source_url, title, anno_name, content, date_added, last_modified = row
        
        if place_id not in downloads:
            downloads[place_id] = {
                'source_url': source_url,
                'title': title,
                'date_added': date_added,
                'last_modified': last_modified
            }
        
        if anno_name == 'downloads/destinationFileURI':
            downloads[place_id]['destination'] = clean_file_uri(content)
        elif anno_name == 'downloads/metaData':
            try:
                metadata = json.loads(content)
                downloads[place_id]['file_size'] = metadata.get('fileSize')
                downloads[place_id]['state'] = metadata.get('state')
                downloads[place_id]['end_time'] = metadata.get('endTime')
            except (json.JSONDecodeError, TypeError):
                pass
    
    if not downloads:
        return None
    
    df = pd.DataFrame.from_dict(downloads, orient='index')
    df = df.reset_index(drop=True)
    
    if 'date_added' in df.columns:
        df['date_added'] = df['date_added'].apply(firefox_time_to_datetime)
    if 'last_modified' in df.columns:
        df['last_modified'] = df['last_modified'].apply(firefox_time_to_datetime)
    if 'end_time' in df.columns:
        df['end_time'] = df['end_time'].apply(firefox_time_ms_to_datetime)
    
    if 'file_size' in df.columns:
        df['file_size_MB'] = (pd.to_numeric(df['file_size'], errors='coerce') / BYTES_TO_MB).round(2)
    
    if 'state' in df.columns:
        df['state'] = df['state'].apply(decode_firefox_download_state)
    
    column_order = ['destination', 'source_url', 'title', 'date_added', 'end_time', 
                    'last_modified', 'file_size', 'file_size_MB', 'state']
    df = df[[col for col in column_order if col in df.columns]]
    
    if 'date_added' in df.columns:
        df = df.sort_values('date_added', ascending=False)
    
    return df

def read_download_history(file_path):
    """Read download history from SQLite file"""
    conn = sqlite3.connect(file_path)
    cursor = conn.cursor()
    
    browser_type = detect_browser_type(cursor)
    
    if browser_type == 'Unknown':
        conn.close()
        return None, browser_type
    
    if browser_type == 'Firefox':
        df = read_firefox_downloads(cursor)
        conn.close()
        return df, browser_type
    
    if browser_type in ['Chrome', 'Edge', 'Chrome/Edge']:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
        if not cursor.fetchone():
            conn.close()
            return None, browser_type
        
        cursor.execute("""
            SELECT id, target_path, site_url, start_time, end_time, received_bytes, total_bytes,
                   state, danger_type, interrupt_reason, opened, referrer, tab_url, mime_type
            FROM downloads
        """)
        rows = cursor.fetchall()
        
        df = pd.DataFrame(rows, columns=['id', 'target_path', 'site_url', 'start_time', 'end_time',
                                          'received_bytes', 'total_bytes', 'state', 'danger_type',
                                          'interrupt_reason', 'opened', 'referrer', 'tab_url', 'mime_type'])
        
        for col in ['start_time', 'end_time']:
            if col in df.columns:
                df[col] = df[col].apply(chrome_time_to_datetime)
        
        if 'received_bytes' in df.columns:
            df['received_MB'] = (pd.to_numeric(df['received_bytes'], errors='coerce') / BYTES_TO_MB).round(2)
        if 'total_bytes' in df.columns:
            df['total_MB'] = (pd.to_numeric(df['total_bytes'], errors='coerce') / BYTES_TO_MB).round(2)
        
        if 'state' in df.columns:
            df['state'] = df['state'].apply(decode_download_state)
        if 'interrupt_reason' in df.columns:
            df['interrupt_reason'] = df['interrupt_reason'].apply(decode_interrupt_reason)
        if 'opened' in df.columns:
            df['opened'] = df['opened'].apply(decode_opened)
        if 'danger_type' in df.columns:
            df['danger_type'] = df['danger_type'].apply(decode_danger_type)
        
        column_order = ['id', 'target_path', 'tab_url', 'referrer', 'start_time', 'end_time',
                        'received_bytes', 'total_bytes', 'received_MB', 'total_MB', 'state', 'danger_type',
                        'interrupt_reason', 'opened', 'mime_type', 'site_url']
        df = df[[col for col in column_order if col in df.columns]]
        
        if 'start_time' in df.columns:
            df = df.sort_values('start_time', ascending=False)
    
    conn.close()
    return df, browser_type

# ============== BOOKMARK FUNCTIONS ==============

def parse_chrome_bookmarks_recursive(node, folder_path=''):
    """Recursively parse Chrome/Edge bookmarks from JSON structure"""
    bookmarks = []
    
    if not isinstance(node, dict):
        return bookmarks
    
    node_type = node.get('type', '')
    node_name = node.get('name', '')
    
    if node_type == 'url':
        bookmarks.append({
            'name': node_name,
            'url': node.get('url', ''),
            'folder': folder_path,
            'date_added': chrome_time_to_datetime(int(node.get('date_added', 0))) if node.get('date_added') else None,
            'date_modified': chrome_time_to_datetime(int(node.get('date_modified', 0))) if node.get('date_modified') else None
        })
    elif node_type == 'folder':
        new_path = f"{folder_path}/{node_name}" if folder_path else node_name
        for child in node.get('children', []):
            bookmarks.extend(parse_chrome_bookmarks_recursive(child, new_path))
    
    # Handle root structure
    if 'roots' in node:
        for root_name, root_node in node['roots'].items():
            if isinstance(root_node, dict):
                bookmarks.extend(parse_chrome_bookmarks_recursive(root_node, ''))
    
    return bookmarks

def read_chrome_edge_bookmarks(file_path):
    """Read Chrome/Edge bookmarks from Bookmarks JSON file"""
    bookmarks_path = Path(file_path).parent / 'Bookmarks'
    
    if not bookmarks_path.exists():
        return None, 'Chrome/Edge'
    
    browser_type = 'Chrome/Edge'
    history_path = Path(file_path).parent / 'History'
    
    if history_path.exists():
        try:
            conn = sqlite3.connect(str(history_path))
            cursor = conn.cursor()
            browser_type = detect_browser_type(cursor)
            conn.close()
        except:
            pass
    
    try:
        with open(bookmarks_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        bookmarks = parse_chrome_bookmarks_recursive(data)
        
        if not bookmarks:
            return None, browser_type
        
        df = pd.DataFrame(bookmarks)
        
        column_order = ['name', 'url', 'folder', 'date_added', 'date_modified']
        df = df[[col for col in column_order if col in df.columns]]
        
        if 'date_added' in df.columns:
            df = df.sort_values('date_added', ascending=False)
        
        return df, browser_type
    
    except (json.JSONDecodeError, IOError) as e:
        print(f"  - Error reading Chrome/Edge bookmarks: {e}")
        return None, browser_type

def read_firefox_bookmarks(file_path):
    """Read Firefox bookmarks from places.sqlite database"""
    conn = sqlite3.connect(file_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_bookmarks'")
    if not cursor.fetchone():
        conn.close()
        return None, 'Firefox'
    
    cursor.execute("""
        SELECT id, title, parent
        FROM moz_bookmarks
        WHERE type = 2
    """)
    folders = {row[0]: {'title': row[1] or '', 'parent': row[2]} for row in cursor.fetchall()}
    
    def get_folder_path(folder_id, visited=None):
        """Recursively build folder path"""
        if visited is None:
            visited = set()
        
        if folder_id not in folders or folder_id in visited:
            return ''
        
        visited.add(folder_id)
        folder = folders[folder_id]
        parent_path = get_folder_path(folder['parent'], visited)
        
        if folder['title']:
            return f"{parent_path}/{folder['title']}" if parent_path else folder['title']
        return parent_path
    
    cursor.execute("""
        SELECT 
            b.id,
            b.title,
            p.url,
            b.parent,
            b.dateAdded,
            b.lastModified
        FROM moz_bookmarks b
        LEFT JOIN moz_places p ON b.fk = p.id
        WHERE b.type = 1 AND p.url IS NOT NULL
    """)
    rows = cursor.fetchall()
    
    conn.close()
    
    if not rows:
        return None, 'Firefox'
    
    bookmarks = []
    for row in rows:
        bm_id, title, url, parent, date_added, last_modified = row
        
        # Skip internal Firefox URLs
        if url and (url.startswith('place:') or url.startswith('about:')):
            continue
        
        folder_path = get_folder_path(parent)
        
        bookmarks.append({
            'name': title or '',
            'url': url,
            'folder': folder_path,
            'date_added': firefox_time_to_datetime(date_added),
            'date_modified': firefox_time_to_datetime(last_modified)
        })
    
    if not bookmarks:
        return None, 'Firefox'
    
    df = pd.DataFrame(bookmarks)
    
    column_order = ['name', 'url', 'folder', 'date_added', 'date_modified']
    df = df[[col for col in column_order if col in df.columns]]
    
    if 'date_added' in df.columns:
        df = df.sort_values('date_added', ascending=False)
    
    return df, 'Firefox'

def read_bookmarks(file_path):
    """Read bookmarks from browser data files"""
    file_path_obj = Path(file_path)
    
    if file_path_obj.name == 'places.sqlite':
        return read_firefox_bookmarks(file_path)
    else:
        return read_chrome_edge_bookmarks(file_path)


def auto_fit_columns(worksheet):
    """Auto-fit column widths based on content and disable text wrapping"""
    for column in worksheet.columns:
        max_length = 0
        column_letter = column[0].column_letter
        column_name = column[0].value
        
        for cell in column:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
            cell.alignment = Alignment(wrap_text=False)
        
        width_limit = 200 if column_name and 'url' in str(column_name).lower() else 100
        worksheet.column_dimensions[column_letter].width = min(max_length + 2, width_limit)


def main():
    start_date, end_date, no_open = parse_arguments()
    
    if start_date or end_date:
        print("\nDate Filter Applied:")
        if start_date:
            print(f"  From: {start_date.strftime('%Y-%m-%d')}")
        if end_date:
            print(f"  To:   {end_date.strftime('%Y-%m-%d')}")
    
    choice = get_user_choice()
    
    script_dir = Path(__file__).parent
    
    history_files = (
        list(script_dir.rglob('History')) + 
        list(script_dir.rglob('History[0-9]*')) + 
        list(script_dir.rglob('places.sqlite'))
    )
    
    if not history_files:
        print("\nNo History files found!")
        print("Please place browser History files in the script directory or subdirectories.")
        return
    
    if choice == 1:
        output_file = OUTPUT_HISTORY
        read_func = read_history_file
        content_type = 'history'
        date_column_map = {
            'Chrome': 'visit_time', 
            'Edge': 'visit_time', 
            'Chrome/Edge': 'visit_time', 
            'Firefox': 'visit_date'
        }
    elif choice == 2:
        output_file = OUTPUT_DOWNLOADS
        read_func = read_download_history
        content_type = 'downloads'
        date_column_map = {
            'Chrome': 'start_time', 
            'Edge': 'start_time', 
            'Chrome/Edge': 'start_time', 
            'Firefox': 'date_added'
        }
    else:
        output_file = OUTPUT_BOOKMARKS
        read_func = read_bookmarks
        content_type = 'bookmarks'
        date_column_map = {
            'Chrome': 'date_added', 
            'Edge': 'date_added', 
            'Chrome/Edge': 'date_added', 
            'Firefox': 'date_added'
        }
    
    if Path(output_file).exists():
        Path(output_file).unlink()
    
    print(f"\nSearching for {content_type}...\n")
    
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        sheet_counters = {}
        sheets_written = 0
        total_records = 0
        
        for hist_file in history_files:
            relative_path = hist_file.relative_to(script_dir)
            print(f"Processing {relative_path}...")
            
            df, browser_type = read_func(str(hist_file))
            
            if df is not None and not df.empty:
                original_count = len(df)
                
                if start_date or end_date:
                    date_column = date_column_map.get(browser_type)
                    if date_column and date_column in df.columns:
                        df = filter_by_date_range(df, date_column, start_date, end_date)
                        filtered_count = len(df)
                        if original_count != filtered_count:
                            print(f"  Filtered: {original_count} → {filtered_count} records")
                
                if df is not None and not df.empty:
                    base_name = browser_type.replace('/', '_')
                    
                    if base_name not in sheet_counters:
                        sheet_counters[base_name] = 0
                    sheet_counters[base_name] += 1
                    
                    if sheet_counters[base_name] == 1:
                        sheet_name = base_name[:31]
                    else:
                        suffix = str(sheet_counters[base_name])
                        sheet_name = f"{base_name[:31-len(suffix)]}{suffix}"
                    
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                    auto_fit_columns(writer.sheets[sheet_name])
                    sheets_written += 1
                    total_records += len(df)
                    
                    print(f"  ✓ {browser_type} {content_type} → '{sheet_name}' ({len(df)} records)")
                else:
                    print(f"  - No records match the date filter")
            else:
                print(f"  - No {content_type} found")
        
        if sheets_written == 0:
            pd.DataFrame({'Message': ['No valid data found']}).to_excel(
                writer, sheet_name='No Data', index=False
            )
            print("\nNo valid data found in any files.")
    
    print("\n" + "=" * 50)
    if sheets_written > 0:
        print(f"✓ {content_type.title()} exported to: {output_file}")
        print(f"  Sheets: {sheets_written}")
        print(f"  Total records: {total_records}")
        
        if not no_open:
            print(f"\nOpening {output_file}...")
            open_file(output_file)
    else:
        print(f"✗ {output_file} created with no data.")

if __name__ == "__main__":
    main()