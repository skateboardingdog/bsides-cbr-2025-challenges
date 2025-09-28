from flask import Flask, render_template, request
import operator

app = Flask(__name__)

TOTALS_ROWS = [6, 7, 8, 9, 10]
TOTALS_COLS = [1, 2, 3, 4, 5]
FLAG = 'skbdg{nytminihasnothingonthis}'

# meh safe enough
def sandbox_eval(s):
	try:
		if len(s) != 5: return 'ERROR'
		return eval(s, {}, {})
	except Exception:
		return 'ERROR'

def lmap(*x):
	return list(map(*x))

@app.route("/")
def srv():
    return render_template('index.html', rows=TOTALS_ROWS, cols=TOTALS_COLS)

@app.post("/verify")
def verify():
	if 'w' not in request.json or type(request.json['w']) != str:
		return {'error': 'bad format'}, 400
	w = request.json['w']
	if len(w) != 25:
		return {'error': 'bad format'}, 400
	if not all(0x20 <= ord(c) <= 0x7f for c in w):
		return {'error': 'crossword entries must be 0x20 < ord(c) < 0x7f'}, 400
	eval_rows = lmap(sandbox_eval, [w[i:i+5] for i in (0,5,10,15,20)])
	eval_cols = lmap(sandbox_eval, [w[i::5] for i in (0,1,2,3,4)])
	rows_ok = lmap(operator.eq, TOTALS_ROWS, eval_rows)
	cols_ok = lmap(operator.eq, TOTALS_COLS, eval_cols)
	return {
		'rows_ok': rows_ok,
		'cols_ok': cols_ok,
		'flag': FLAG if all(rows_ok) and all(cols_ok) else ''
	}, 200