import json
import subprocess
import sys


def test_cli_demo_and_replay(tmp_path):
    command=[sys.executable,'-m','signaldesk.cli','--db',str(tmp_path/'cli.sqlite'),'demo']
    first=subprocess.run(command,capture_output=True,text=True,check=True)
    second=subprocess.run(command,capture_output=True,text=True,check=True)
    assert json.loads(first.stdout)['detection']['created']==5
    assert json.loads(second.stdout)['import']['inserted']==0
