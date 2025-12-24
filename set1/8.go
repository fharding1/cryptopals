package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
)

func main() {
	f, _ := os.Open("8.txt")
	defer f.Close()

	scanner := bufio.NewScanner(f)

	var k int
	for scanner.Scan() {
		line := scanner.Text()
		b, _ := hex.DecodeString(line)
		var i int
	CheckLoop:
		for v := range slices.Chunk(b, 16) {
			var j int
			for w := range slices.Chunk(b, 16) {
				if i != j && slices.Equal(v, w) {
					fmt.Println(i, j, hex.EncodeToString(v), k)
					break CheckLoop
				}
				j++
			}
			i++
		}
		k++
	}
}
