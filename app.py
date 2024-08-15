from flask import Flask, request, render_template
import os
import zipfile
import re
from typing import List, Dict
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

patterns = {
    'brokenaccesscontrol': ['wp_ajax_nopriv', 'is_admin'],
    'csrf': ['admin_init', 'wp_ajax', 'wp_ajax_nopriv', 'admin_post', 'admin_post_nopriv', 'admin_action', 'admin_menu'],
    'fileuploadrce': ['$_FILES', 'file_put_contents', 'fopen', 'fwrite', 'move_uploaded_file', "$_FILES['type']"],
    'xss': ['$_POST', '$_GET', '$_REQUEST', '$_SERVER', '$_COOKIE', '$_FILES'],
    'sqli': ['$wpdb->get_results(', '$wpdb->query(', '$wpdb->get_row(', '$wpdb->get_col('],
    'phpcodeinject': ['exec(', 'shell_exec(', 'proc_open(', 'system(', 'passthru(', 'eval('],
    'lfi_rfi': ['include_once(', 'include(', 'require_once(', 'require('],
    'lfi_readfile': ['file_get_contents(', 'fread(', 'fopen('],
    'lfi_deletefile': ['wp_delete_file(', 'unlink('],
    'privis': ['user_meta'],
    'optionupdatevuln': ['update_option(', 'update_user_meta('],
    'openredirect': ['wp_redirect()']
}

def create_graph(results: Dict[str, Dict[str, List[Dict[str, int]]]]) -> str:
    category_counts = {key: 0 for key in patterns.keys()}
    
    # Đếm số lượng phát hiện cho mỗi loại
    for file_results in results.values():
        for key in file_results:
            category_counts[key] += len(file_results[key])
    
    # Tạo đồ thị
    fig, ax = plt.subplots()
    categories = list(category_counts.keys())
    counts = list(category_counts.values())
    
    ax.bar(categories, counts, color='skyblue')
    ax.set_xlabel('Categories')
    ax.set_ylabel('Count')
    ax.set_title('Count of Matches for Each Category')
    plt.xticks(rotation=45, ha='right')
    
    # Lưu đồ thị vào bộ nhớ
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close()
    
    # Chuyển đổi hình ảnh thành chuỗi base64
    img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')
    return img_base64

def extract_zip(zip_path: str, extract_to: str) -> bool:
    if not zipfile.is_zipfile(zip_path):
        print(f"{zip_path} is not a valid ZIP file.")
        return False

    try:
        os.makedirs(extract_to, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        return True
    except Exception as e:
        print(f"An error occurred while extracting {zip_path}: {e}")
        return False

def search_file(file_path: str, search_patterns: Dict[str, List[str]]) -> Dict[str, List[Dict[str, int]]]:
    matches = {key: [] for key in search_patterns}
    try:
        with open(file_path, 'r', errors='ignore') as file:
            for line_num, line in enumerate(file, start=1):
                for key, patterns in search_patterns.items():
                    for pattern in patterns:
                        if re.search(re.escape(pattern), line):
                            matches[key].append({'pattern': pattern, 'line': line_num})
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return matches

def crawl_directory(root_dir: str, search_patterns: Dict[str, List[str]]) -> Dict[str, Dict[str, List[Dict[str, int]]]]:
    results = {}
    for subdir, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(subdir, file)
            file_results = search_file(file_path, search_patterns)
            if any(file_results.values()):
                results[file_path] = file_results
    return results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename.endswith('.zip'):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            extract_dir = os.path.splitext(file_path)[0]
            os.makedirs(extract_dir, exist_ok=True)
            if extract_zip(file_path, extract_dir):
                results = crawl_directory(extract_dir, patterns)
                plot_img = create_graph(results)
                return render_template('results.html', results=results, plot_img=plot_img)
            else:
                return "Failed to extract the ZIP file."
        else:
            return "Please upload a valid ZIP file."
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=False)
