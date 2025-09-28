# Solve

Challenge is a Go binary, without the function names stripped, making it easier to identify which functions are relevant, and which are Go runtime libraries or from the Fyne framework (irrelevant to solving the challenge). Challenge is Go does things a little differently to C programs, especially when it comes to calling conventions, types (especially slices), and how Go routines enable asynchronous functions.

Relevant code is `main.main` and `bigmaze/maze/*`

Basic idea of the challenge:
- Solve the maze
- Get the characters that are sent in a go channel according to the position of the player. The right path will result in the flag

Go reversing tips:
- GoReSym is very helpful with recovering function signatures and types

## Recreating then solving the maze

Follow the flow of the application to get to the point where the maze is created.

`main.main` > `bigmaze/maze/gui.Start` > `bigmaze/maze/gui.mazeContent` > `bigmaze/maze/gui.decodeMaze`

Slice @ `0x017d6d30` (length 0x3d09) is passed into `bigmaze/maze/gui.decodeMaze`, so this data is being decoded into a maze.

Rough recreation (based on Ghidra disassembly with default auto analysis):

```
decodeMaze(in_RAX, in_RBX, in_RCX){
    encodedMaze = in_RAX
    mazeLength = in_RBX
    counter = 0
    2d_array = createSlice()
    for (i = 0; i < 0x7d; i++) {
        1d_array = createSlice()
        for (j = 0; j < 0x7d; j++>) {
            wall = byteToWall(encodedMaze[counter])
            cell = new(model.Cell)
            cell = {wall, i, j, 0}
        }
    }
}

byteToWall(in_AL) {
    byte = in_AL
    array = [0, 0, 0, 0, 0, 0, 0, 0]
    if ((byte >> 3) & 1 == 1) {
        array[3] = 1
    }
    if ((byte >> 2) & 1 == 1) {
        array[0] = 1
    }
    if ((byte >> 1) & 1 == 1) { 
        array[2] = 1
    }
    if (byte & 1 == 1) {
        array[1] = 1
    }
    out_eax = array[3] # top
    out_ebx = array[2] # bottom
    out_cl = array[1] # left
    out_dil = array[0] # right
    return (model.CellWalls)out_*
}

// From GoReSym
VA: 0x11368e0
type model.Cell struct {
    Walls      model.CellWalls
    Loc        model.CellLocation
    Role       model.CellRole
}

VA: 0x114dfe0
type model.CellWalls struct {
    Top        bool
    Bottom     bool
    Left       bool
    Right      bool
}

VA: 0x111e120
type model.CellLocation struct {
    RowIndex   int
    ColumnIndex int
}

VA: 0x109ef20
type model_CellRole int;

```

From here the maze can be recreated and solved separately (example in `solve.py`)

In the binary, `bigmaze/maze/gamelogic.(*game).SetupFlagLogic` sets up the mapping of characters to position. A go channel is created and `bigmaze/maze/gamelogic.positionToChar` is called

in `positionToChar`:
- A large slice of data @ offset 0x17daa39 of size 0x3d09 is assigned to a variable 
- a value (consisting of 2 integers) is read from the go channel
- position = int1 * 0x7d + int2
- character = data[position]

Using the path obtained from solving the maze, then getting the appropriate character from the large chunk of data yields the following:
```
welcome to the maze solve this and find the rest of the message. as you step inside you might notice that the walls feel almost endless stretching out in every direction it is certainly and without question a maze and not some other kind of unusual puzzle hidden inside another maze hoc non difficile erit igitur viam invenire potes have you ever noticed how some people always choose the left turn in a maze while others insist on always turning right and both groups are convinced that their method is the best anyway i will describe the flag as you make your way through this maze and i encourage you to pay attention because sometimes details can slip past when you least expect it good luck and have fun as you continue walking and exploring the twists and turns of this place now a small reminder any letters in the flag will all be lowercase and they will consist of several words each one separated by an underscore and i find it interesting how underscores almost look like little paths connecting words together which feels appropriate for a maze of words of course the flag is in flag format and it will begin with skbdg and i promise it is not the short form of skibidi dog anyway that is then followed by an open curly brace and speaking of curly things have you ever thought about how curly vines growing on a wall can look like strange writing from another language next comes a few fun parts of the flag the very first word is golang and while we mention golang it is worth remembering how many people start programming projects with good intentions but end up creating their own labyrinth of code following that the next word is reversing then the third word is can which is simple and short yet powerful with the word after that being be which makes me think of the phrase to be or not to be then the last word of the flag is fun and what better way to finish a journey through a maze than to call it fun and finally you must close the flag with a closed curly brace jst as you would close a door after leaving a mysterious and puzzling place
```

Mainly focusing on:
> any letters in the flag will all be lowercase
> several words each one separated by an underscore
> flag is in flag format and it will begin with skbdg
> followed by an open curly brace
> the very first word is golang
> the next word is reversing
> the third word is can
> with the word after that being be
> then the last word of the flag is fun
> close the flag with a closed curly brace

skbdg{golang_reversing_can_be_fun}