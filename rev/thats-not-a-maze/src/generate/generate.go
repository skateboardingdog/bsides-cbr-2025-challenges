package generate

// creates the maze - not to be added with published maze

import (
	"bigmaze/maze/model"
	"math/rand"
	"fmt"
)

type metaCell struct {
	Cell *model.Cell 
	Visited bool
}

type stack struct {
	cells []*model.Cell
}

func (s *stack) Push(cell *model.Cell) {
	s.cells = append(s.cells, cell)
}

func (s *stack) Pop() *model.Cell {
	count := len(s.cells)
	if count == 0 {
		return nil 
	}
	cell := s.cells[count-1]
	s.cells = s.cells[:count-1]
	return cell
}

func newMetaMaze(maze [][]*model.Cell) [][]*metaCell {
	size := len(maze)
	metaMaze := make([][]*metaCell, size)
	for y := 0; y < size; y++ {
		metaMaze[y] = make([]*metaCell, size)
		for x:= 0; x < size; x++ {
			metaMaze[y][x] = &metaCell {
				Cell: maze[y][x],
				Visited: false,
			}
		}
	}
	return metaMaze
}

func checkNeighbour(maze [][]*metaCell, currLoc model.CellLocation) []*metaCell{
	neighbours := []*metaCell{}
	size := len(maze)
	currX := currLoc.ColumnIndex
	currY := currLoc.RowIndex
	// get top
	if currY - 1 >= 0 { 
		if !maze[currY - 1][currX].Visited {
			neighbours = append(neighbours, maze[currY - 1][currX])
		}
	}
	// get right 
	if currX + 1 < size {
		if !maze[currY][currX + 1].Visited {
			neighbours = append(neighbours, maze[currY][currX + 1])
		}
	}
	// get bottom 
	if currY + 1< size {
		if !maze[currY + 1][currX].Visited {
			neighbours = append(neighbours, maze[currY + 1][currX])
		}
	}
	// get left
	if currX - 1 >= 0 {
		if !maze[currY][currX - 1].Visited {
			neighbours = append(neighbours, maze[currY][currX - 1])
		}
	}

	return neighbours
}

func removeWalls(cellA, cellB *model.Cell) {
	if cellA.Loc.RowIndex < cellB.Loc.RowIndex {
		cellA.Walls.Bottom = false 
		cellB.Walls.Top = false 
		return
	}

	if cellA.Loc.RowIndex > cellB.Loc.RowIndex {
		cellA.Walls.Top = false 
		cellB.Walls.Bottom = false 
		return
	}

	if cellA.Loc.ColumnIndex < cellB.Loc.ColumnIndex {
		cellA.Walls.Right = false 
		cellB.Walls.Left = false 
		return
	}

	if cellA.Loc.ColumnIndex > cellB.Loc.ColumnIndex {
		cellA.Walls.Left = false 
		cellB.Walls.Right = false
		return
	}
}

func wallsToByte(walls model.CellWalls) byte {
	var res byte 
	wallBool := []bool{walls.Top, walls.Right, walls.Bottom, walls.Left}
	for _, b := range wallBool {
		res <<= 1
		if b {
			res |= 1
		}
	}
	return res
}

func SetupGrid(size int) []byte{
	maze := make([][]*model.Cell, size)
	for y := 0; y < size; y++ {
		maze[y] = make([]*model.Cell, size)
		for x:= 0; x < size; x++ {
			maze[y][x] = &model.Cell{
				Walls: model.CellWalls{Top: true, Bottom: true, Left: true, Right: true},
				Loc: model.CellLocation{RowIndex: y, ColumnIndex: x},
				Role: model.CellRolePath,
			}
		}
	}

	maze[0][0].Role = model.CellRoleStart
	maze[size-1][size-1].Role = model.CellRoleFinish

	metaMaze := newMetaMaze(maze)
	currLoc := model.CellLocation{RowIndex: 0, ColumnIndex: 0}

	visStack := stack{}
	for {
		curr := metaMaze[currLoc.RowIndex][currLoc.ColumnIndex]
		curr.Visited = true 
		neighbours := checkNeighbour(metaMaze, currLoc)
		if len(neighbours) > 0 {
			next := neighbours[rand.Intn(len(neighbours))]
			
			// clear walls between two
			nextCell := next.Cell
			currCell := curr.Cell 
			visStack.Push(currCell)
			removeWalls(currCell, nextCell)
			currLoc = nextCell.Loc 
		} else {
			prevCell := visStack.Pop()
			if prevCell == nil {
				break
			}
			currLoc = prevCell.Loc
		}
	}

	// encode maze 
	encodedMaze := []byte{}
	var encodedWall byte
	for y := 0; y < len(maze); y++ {
		for x := 0; x < len(maze[y]); x++ {
			singleCell := maze[y][x]
			encodedWall = wallsToByte(singleCell.Walls)
			encodedMaze = append(encodedMaze, encodedWall)
		}
	}

	fmt.Println(encodedMaze)
	return encodedMaze
}

