"""
Solving by hand is more fun. But you could do this too.
"""

from z3 import *

def solve_crossword_z3(row_words, col_words):
    solver = Solver()
    
    row_choices = [Int(f'row_{i}') for i in range(5)]
    col_choices = [Int(f'col_{j}') for j in range(5)]
    
    grid = [[Int(f'cell_{i}_{j}') for j in range(5)] for i in range(5)]
    
    # Constraints: choices must be valid indices
    for i in range(5):
        solver.add(And(row_choices[i] >= 0, row_choices[i] < len(row_words[i])))
        solver.add(And(col_choices[i] >= 0, col_choices[i] < len(col_words[i])))
    
    # Constraints: row words must match the chosen row word
    for i in range(5):
        row_constraints = []
        for word_idx, word in enumerate(row_words[i]):
            if len(word) == 5:
                word_constraint = And(
                    row_choices[i] == word_idx,
                    And([grid[i][j] == ord(word[j].upper()) for j in range(5)])
                )
                row_constraints.append(word_constraint)
        
        if row_constraints:
            solver.add(Or(row_constraints))
        else:
            print(f"Warning: No valid words for row {i}")
            return None
    
    # Constraints: column words must match the chosen column word
    for j in range(5):
        col_constraints = []
        for word_idx, word in enumerate(col_words[j]):
            if len(word) == 5:  # Ensure word is exactly 5 characters
                word_constraint = And(
                    col_choices[j] == word_idx,
                    And([grid[i][j] == ord(word[i].upper()) for i in range(5)])
                )
                col_constraints.append(word_constraint)
        
        if col_constraints:
            solver.add(Or(col_constraints))
        else:
            print(f"Warning: No valid words for column {j}")
            return None
    
    # Solve the constraints
    if solver.check() == sat:
        model = solver.model()
        
        selected_rows = []
        selected_cols = []
        
        for i in range(5):
            row_idx = model[row_choices[i]].as_long()
            selected_rows.append(row_words[i][row_idx])
            
            col_idx = model[col_choices[i]].as_long()
            selected_cols.append(col_words[i][col_idx])
        
        grid_solution = []
        for i in range(5):
            row = []
            for j in range(5):
                char_code = model[grid[i][j]].as_long()
                row.append(chr(char_code))
            grid_solution.append(''.join(row))
        
        return selected_rows, selected_cols, grid_solution
    else:
        return None

def print_solution(result):
    if result is None:
        print("No solution found!")
        return
    
    selected_rows, selected_cols, grid = result
    
    print("Solution found!")
    print("\nSelected row words:")
    for i, word in enumerate(selected_rows):
        print(f"  Row {i}: {word}")
    
    print("\nSelected column words:")
    for j, word in enumerate(selected_cols):
        print(f"  Col {j}: {word}")
    
    print("\nGrid:")
    for row in grid:
        print(f"  {' '.join(row)}")

def sandbox_eval(s):
    try:
        if len(s) != 5: return -99999
        return eval(s, {}, {})
    except Exception:
        return -99999

import itertools

zz = [[] for _ in range(10)]
for a,b,c,d,e in itertools.product('1234567890#%^&*~|+- ', repeat=5):
    
    s = a+b+c+d+e
    u = sandbox_eval(s)
    if u in (1,2,3,4,5,6,7,8,9,10):
        zz[[1,2,3,4,5,6,7,8,9,10].index(int(u))].append(s)

row_words = zz[:5]
    
col_words = zz[5:]
    
print("Solving crossword with Z3...")
print("Row word options:")
for i, words in enumerate(row_words):
    print(f"  Row {i}: {words}")

print("\nColumn word options:")
for j, words in enumerate(col_words):
    print(f"  Col {j}: {words}")

print("\n" + "="*50)

result = solve_crossword_z3(row_words, col_words)
print_solution(result)

