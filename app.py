from flask import Flask, render_template_string
import os
import json
from datetime import datetime
import base64
from io import BytesIO
import matplotlib
matplotlib.use('Agg')  # Use a non-GUI backend so it can work on servers
import matplotlib.pyplot as plt

app = Flask(__name__)

def get_sarcastic_remark(accuracy):
    """Return a sarcastic remark based on accuracy."""
    if accuracy >= 90:
        return "Wow, over 90% accuracy. I bet it had a dictionary of answers handy."
    elif accuracy >= 80:
        return "Over 80% accuracy, not too shabby. Probably cheated a little, though."
    elif accuracy >= 70:
        return "Around 70% accuracy. Pretty good... for a glorified autocomplete machine."
    elif accuracy >= 60:
        return "60%+ accuracy. I guess it's passable, like a student who barely studied."
    else:
        return "Below 60% accuracy. Yikes. Did it even try?"

def get_metric_class(value, is_percentage=False):
    """
    Return a CSS class based on the metric value.
    If is_percentage=True, value is expected as a percentage (0-100).
    Otherwise, value is expected as a fraction (0.0-1.0).
    """
    if is_percentage:
        # For accuracy (which is a percentage)
        if value < 60:
            return "metric-bad"
        elif value < 80:
            return "metric-decent"
        else:
            return "metric-good"
    else:
        # For precision, recall, f1 which are 0.0 to 1.0
        if value < 0.6:
            return "metric-bad"
        elif value < 0.8:
            return "metric-decent"
        else:
            return "metric-good"

def generate_metrics_chart(metrics):
    """
    Generate a Matplotlib bar chart of basic metrics, 
    encode it in base64, and return the string for embedding in HTML.
    """
    # Extract numeric metrics. 
    # Convert Accuracy from percentage to a fraction (e.g., 87% -> 0.87).
    accuracy_fraction = metrics.get("Accuracy (%)", 0) / 100.0
    precision = metrics.get("Precision", 0)
    recall = metrics.get("Recall", 0)
    f1_score = metrics.get("F1-Score", 0)

    # Create lists for plotting
    metric_labels = ["Accuracy", "Precision", "Recall", "F1-Score"]
    metric_values = [accuracy_fraction, precision, recall, f1_score]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(metric_labels, metric_values, color=['#1f77b4', '#2ca02c', '#ff7f0e', '#d62728'])
    ax.set_ylim([0, 1])
    ax.set_ylabel("Value")
    ax.set_title("Model Performance Metrics")

    # Convert plot to base64
    buffer = BytesIO()
    fig.savefig(buffer, format='png', bbox_inches='tight')
    buffer.seek(0)
    encoded_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close(fig)

    return encoded_image

def generate_label_charts(report_dict):
    """
    For each label (except 'accuracy', 'macro avg', 'weighted avg'), 
    generate a bar chart of precision, recall, F1-score.
    Returns a dict: {label_name: base64_image_string}
    """
    charts = {}

    # Exclude keys that are not actual labels
    skip_keys = {'accuracy', 'macro avg', 'weighted avg'}

    for label, metrics in report_dict.items():
        if label in skip_keys:
            continue  # skip overall stats

        precision = metrics["precision"]
        recall = metrics["recall"]
        f1 = metrics["f1-score"]

        # Create a figure for this label
        fig, ax = plt.subplots(figsize=(3, 3))
        bar_labels = ["Precision", "Recall", "F1-score"]
        bar_vals = [precision, recall, f1]

        ax.bar(bar_labels, bar_vals, color=['#1f77b4', '#2ca02c', '#d62728'])
        ax.set_ylim([0, 1])
        ax.set_title(label)
        ax.set_ylabel("Score")

        # Convert plot to base64
        buf = BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        plt.close(fig)

        charts[label] = img_b64

    return charts

def generate_confusion_matrix_chart(cm, class_names):
    """
    Generate a Matplotlib figure of the confusion matrix,
    then return a base64-encoded string for embedding in HTML.
    """
    # Convert cm to a numpy array if you like
    import numpy as np
    cm_array = np.array(cm)
    
    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.imshow(cm_array, interpolation='nearest', cmap=plt.cm.Blues)
    ax.set_title("Confusion Matrix")
    fig.colorbar(cax)

    # Tick labels
    ax.set_xticks(range(len(class_names)))
    ax.set_yticks(range(len(class_names)))
    ax.set_xticklabels(class_names, rotation=45, ha="right")
    ax.set_yticklabels(class_names)

    # Add labels to each cell
    threshold = cm_array.max() / 2.
    for i in range(cm_array.shape[0]):
        for j in range(cm_array.shape[1]):
            value = cm_array[i, j]
            color = "white" if value > threshold else "black"
            ax.text(j, i, format(value, "d"),
                    horizontalalignment="center",
                    color=color)

    ax.set_ylabel('True label')
    ax.set_xlabel('Predicted label')

    # Convert figure to base64
    buf = BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    plt.close(fig)

    return img_b64


INDEX_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">
    <title>JSON Output Viewer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f9f9f9;
        }
        h1 {
            font-size: 32px;
            margin-bottom: 20px;
        }
        p {
            margin-bottom: 20px;
        }
        .file-list {
            list-style: none;
            padding: 0;
        }
        .file-list li {
            background: #ffffff;
            margin: 10px 0;
            padding: 15px;
            border: 1px solid #eee;
            border-radius: 4px;
        }
        a {
            text-decoration: none;
            font-weight: bold;
            color: #2c3e50;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>JSON Results</h1>
    <p>Below are the generated JSON result files. Click on one to view its details.</p>
    <ul class="file-list">
    {% for file in files %}
        <li><a href="{{ file }}">{{ file }}</a></li>
    {% endfor %}
    </ul>
</body>
</html>
"""

DETAIL_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">
    <title>{{ filename }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f9f9f9;
        }
        h1, h2 {
            margin: 0 0 20px;
        }
        .metadata {
            background: #ffffff;
            padding: 20px;
            border-radius: 4px;
            border: 1px solid #eee;
            margin-bottom: 20px;
        }
        .metadata h2 {
            margin-top: 0;
        }
        .metrics-table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 10px;
        }
        .metrics-table th, .metrics-table td {
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        .metrics-table th {
            background: #f2f2f2;
        }

        /* Metric color classes */
        .metric-bad {
            color: #d9534f; /* red */
            font-weight: bold;
        }
        .metric-decent {
            color: #f0ad4e; /* yellow-ish */
            font-weight: bold;
        }
        .metric-good {
            color: #5cb85c; /* green */
            font-weight: bold;
        }

        .remark {
            font-style: italic;
            color: #555;
            margin-top: 10px;
        }

        .chart-container {
            margin-bottom: 20px;
            text-align: center;
        }
        .chart-container img {
            max-width: 600px;
            border: 1px solid #ccc;
            background: #fff;
        }
        .label-charts {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .label-chart {
            background: #fff;
            border: 1px solid #ccc;
            border-radius: 4px;
            padding: 15px;
            text-align: center;
        }
        .label-chart img {
            width: 100%;
            height: auto;
            display: block;
            margin: 0 auto;
        }

        .data-table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
            background: #ffffff;
            border: 1px solid #eee;
            border-radius: 4px;
        }
        .data-table th, .data-table td {
            border-bottom: 1px solid #ddd;
            padding: 10px;
            vertical-align: top;
            word-break: break-word;
        }
        .data-table th {
            background: #f2f2f2;
        }

        a {
            display: inline-block;
            margin-bottom: 20px;
            text-decoration: none;
            font-weight: bold;
            color: #2c3e50;
        }
        a:hover {
            text-decoration: underline;
        }

    </style>
</head>
<body>
    <a href="/">← Back</a>
    <h1>Results for: {{ metadata.model_name }} - {{ metadata.metrics["Accuracy (%)"]|round(2) }}%</h1>
    <div class="metadata">
        <h2>Metadata</h2>
        <p><strong>Date of Test:</strong> {{ human_time }}</p>
        <p><strong>Model Name:</strong> {{ metadata.model_name }}</p>
        <p><strong>Total Samples:</strong> {{ metadata.total_samples }}</p>
        <p><strong>Total Execution Time:</strong> {{ metadata.elapsed_time }}</p>
        <p><strong>Noun Group:</strong> {{ metadata.noun_group }}</p>

        <h2>Metrics</h2>
        <table class="metrics-table">
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Accuracy (%)</td>
                <td class="{{ metric_classes['Accuracy (%)'] }}">{{ metadata.metrics["Accuracy (%)"]|round(4) }}%</td>
            </tr>
            <tr>
                <td>Precision</td>
                <td class="{{ metric_classes['Precision'] }}">{{ metadata.metrics["Precision"]|round(4) }}</td>
            </tr>
            <tr>
                <td>Recall</td>
                <td class="{{ metric_classes['Recall'] }}">{{ metadata.metrics["Recall"]|round(4) }}</td>
            </tr>
            <tr>
                <td>F1-Score</td>
                <td class="{{ metric_classes['F1-Score'] }}">{{ metadata.metrics["F1-Score"]|round(4) }}</td>
            </tr>
        </table>

        <div class="remark">{{ remark }}</div>
    </div>
    <h2>Per-Label Metrics</h2>
<table class="label-results-table">
    <thead>
        <tr>
            <th>Label</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1-Score</th>
            <th>Support</th>
        </tr>
    </thead>
    <tbody>
    {% for label, stats in metadata.metrics.classification_report.items() %}
        {% if label not in ["accuracy", "macro avg", "weighted avg"] %}
        <tr>
            <td>{{ label }}</td>
            <td>{{ stats.precision|round(4) }}</td>
            <td>{{ stats.recall|round(4) }}</td>
            <td>{{ stats["f1-score"]|round(4) }}</td>
            <td>{{ stats.support }}</td>
        </tr>
        {% endif %}
    {% endfor %}
    </tbody>
</table>


    <!-- Overall Metrics Chart -->
<div class="chart-container">
    <h2>Overall Metrics Chart</h2>
    <img src="data:image/png;base64,{{ metrics_chart }}" alt="Overall Metrics Chart"/>
</div>

<!-- Per-Class Metrics -->
<h2>Per-Class Metrics</h2>
    <div class="label-charts">
    {% for label, chart_b64 in label_charts.items() %}
        <div class="label-chart">
            <h3>{{ label }}</h3>
            <img src="data:image/png;base64,{{ chart_b64 }}" alt="Chart for {{ label }}">
        </div>
    {% endfor %}
    </div>

<!-- Confusion Matrix -->
<div class="chart-container">
    <h2>Confusion Matrix</h2>
    <img src="data:image/png;base64,{{ confusion_matrix_chart }}" alt="Confusion Matrix Chart"/>
</div>

<h2>Data</h2>
    <table class="data-table">
        <thead>
            <tr>
            {% for col in data_columns %}
                <th>{{ col }}</th>
            {% endfor %}
            </tr>
        </thead>
        <tbody>
        {% for row in data %}
            <tr>
            {% for col in data_columns %}
                <td>{{ row[col] }}</td>
            {% endfor %}
            </tr>
        {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

@app.route('/')
def index():
    json_folder = 'json_output'
    files = [f for f in os.listdir(json_folder) if f.endswith('.json')]
    return render_template_string(INDEX_TEMPLATE, files=files)

@app.route('/<path:filename>')
def show_json(filename):
    json_folder = 'json_output'
    file_path = os.path.join(json_folder, filename)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        metadata = data.get('metadata', {})
        metrics = metadata.get('metrics', {})

        # Overall metrics
        accuracy_pct = metrics.get("Accuracy (%)", 0)
        remark = get_sarcastic_remark(accuracy_pct)

        # classification_report dict
        report_dict = metrics.get('classification_report', {})
        skip_keys = {"accuracy", "macro avg", "weighted avg"}
        class_names = [lbl for lbl in report_dict.keys() if lbl not in skip_keys]

        # Generate the label bar charts
        label_charts = generate_label_charts(report_dict)

        # Generate overall metrics chart
        metrics_chart = generate_metrics_chart(metrics)

        # Generate confusion matrix chart
        cm = metrics.get("confusion_matrix", [])
        confusion_matrix_chart = generate_confusion_matrix_chart(cm, class_names)

        # Convert stored timestamp -> human_time
        raw_timestamp = metadata.get('timestamp', '')
        dt = datetime.strptime(raw_timestamp, "%B_%d_%Y_%I%M%p")
        human_time = dt.strftime("%B %d, %Y at %I:%M%p")

        # CSS classes
        metric_classes = {
            "Accuracy (%)": get_metric_class(metrics.get("Accuracy (%)", 0), is_percentage=True),
            "Precision": get_metric_class(metrics.get("Precision", 0.0)),
            "Recall": get_metric_class(metrics.get("Recall", 0.0)),
            "F1-Score": get_metric_class(metrics.get("F1-Score", 0.0)),
        }

        # Data table
        data_records = data.get('data', [])
        data_columns = list(data_records[0].keys()) if data_records else []

        return render_template_string(
            DETAIL_TEMPLATE,
            filename=filename,
            metadata=metadata,
            remark=remark,
            human_time=human_time,
            metric_classes=metric_classes,
            data=data_records,
            data_columns=data_columns,
            metrics_chart=metrics_chart,
            label_charts=label_charts,
            confusion_matrix_chart=confusion_matrix_chart
        )
    else:
        return "File not found", 404



if __name__ == '__main__':
    app.run(debug=True)
