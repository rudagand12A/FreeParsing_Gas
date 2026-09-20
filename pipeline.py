name: Auto Update VPN Config (Every 9 Hours)

on:
  schedule:
    - cron: '0 */9 * * *'
  workflow_dispatch:

jobs:
  run-aggregator:
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
    - name: Checkout Code
      uses: actions/checkout@v4

    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.10'

    - name: Run Pipeline Script
      run: python pipeline.py

    - name: Commit and Push sub_1212.json
      run: |
        git config --global user.name "github-actions[bot]"
        git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"
        git add output/sub_1212.json
        git diff-index --quiet HEAD || git commit -m "🚀 Автообновление: $(date +'%Y-%m-%d %H:%M:%S')"
        git push
