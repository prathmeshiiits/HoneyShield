import urllib.request
import sys

sys.stdout.reconfigure(encoding='utf-8')

html = urllib.request.urlopen('http://127.0.0.1:5000/admin').read().decode()

def extract_section(start_str, end_str):
    pos1 = html.find(start_str)
    if pos1 == -1: return 'NOT FOUND'
    pos2 = html.find(end_str, pos1)
    return html[pos1:pos2+len(end_str)] if pos2 != -1 else html[pos1:pos1+1500]

print('=== ATTEMPTS CHART CARD ===')
print(extract_section('id="attemptsChartCard"', '</article>'))

print('\n=== RISK DISTRIBUTION CARD ===')
print(extract_section('id="riskDistributionCard"', '</article>'))
