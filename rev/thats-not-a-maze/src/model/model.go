package model 

type CellWalls struct {
	Top		bool 
	Bottom	bool 
	Left 	bool 
	Right 	bool
}

type CellLocation struct {
	RowIndex 	int 
	ColumnIndex	int 
}

type CellRole int 

type Cell struct {
	Walls CellWalls 
	Loc CellLocation 
	Role CellRole 
}

const (
	CellRolePath	CellRole = 0 
	CellRoleStart	CellRole = 1
	CellRoleFinish	CellRole = 2
)