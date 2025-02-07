package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

const (
	MaxGoroutines        = 4 // Adjust based on your CPU
	SaveInterval         = 10 * time.Second
	AllPositionsAreKnown = true
)

type Progress struct {
	LastIndex      int64    `json:"last_index"`
	TestedCombos   int64    `json:"tested_combinations"`
	KnownWords     []string `json:"known_words"`
	KnownPositions []int    `json:"known_positions"`
}

func main() {
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println("\nShutting down gracefully...")
		cancel()
	}()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Please write as many words as you have (space-separated):")
	knownWordsInput, _ := reader.ReadString('\n')
	knownWords := strings.Fields(strings.TrimSpace(knownWordsInput))

	fmt.Println("Please give me the wallet address you would like to match:")
	targetAddr, _ := reader.ReadString('\n')
	targetAddr = strings.TrimSpace(targetAddr)

	if len(knownWords) == 12 {
		mnemonic := strings.Join(knownWords, " ")
		if address, ok := checkWallet(mnemonic, targetAddr); ok {
			fmt.Printf("Found match!\nAddress: %s\nMnemonic: %s\n", address, mnemonic)
		} else {
			fmt.Printf("No match found.\nGenerated address: %s\n", address)
		}

		return
	}

	fmt.Println("Entering brute-force mode!")

	// Load BIP39 wordlist
	wordlist := bip39.GetWordList()

	// Load progress if exists
	progress := loadProgress()
	if progress == nil {
		progress = &Progress{
			LastIndex:      -1,
			TestedCombos:   0,
			KnownWords:     knownWords,
			KnownPositions: make([]int, len(knownWords)),
		}
		// Fill known positions - you'll need to input these
		fmt.Println("For each known word, enter its position (0-11):")
		for i, word := range knownWords {
			if AllPositionsAreKnown {
				fmt.Println(
					"We are assuming all positions are known. " +
						"you can set AllPositionsAreKnown to false to make me ask you the positions.")
				progress.KnownPositions[i] = i
			} else {
				fmt.Printf("Position for '%s': ", word)
				var pos int
				fmt.Scanf("%d", &pos)
				progress.KnownPositions[i] = pos
			}
		}
	}

	// Create work channel and wait group
	jobs := make(chan []string, MaxGoroutines)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < MaxGoroutines; i++ {
		wg.Add(1)
		go worker(ctx, jobs, &wg, targetAddr, progress)
	}

	// Start progress saver
	go saveProgressPeriodically(ctx, progress)

	// Generate and test combinations
	missingCount := 12 - len(knownWords)
	totalCombinations := pow(len(wordlist), missingCount)

	fmt.Printf("Total combinations to test: %d\n", totalCombinations)
	fmt.Printf("Estimated time: %v (at 1000 checks/sec)\n", time.Duration(totalCombinations/1000)*time.Second)

	generateCombinations(ctx, wordlist, progress, jobs)

	close(jobs)
	wg.Wait()

	fmt.Printf("\nTested %d combinations\n", atomic.LoadInt64(&progress.TestedCombos))
}

func worker(ctx context.Context, jobs <-chan []string, wg *sync.WaitGroup, targetAddr string, progress *Progress) {
	defer wg.Add(-1)

	for words := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			if address, ok := checkWallet(strings.Join(words, " "), targetAddr); ok {
				fmt.Printf("\nFOUND MATCH!\nAddress: %s\nWords: %s\n", address, strings.Join(words, " "))
				os.Exit(0)
			}
			atomic.AddInt64(&progress.TestedCombos, 1)
		}
	}
}

func generateCombinations(ctx context.Context, wordlist []string, progress *Progress, jobs chan<- []string) {
	words := make([]string, 12)

	// Fill known words
	for i, word := range progress.KnownWords {
		words[progress.KnownPositions[i]] = word
	}

	// Get positions that need to be filled
	var missingPositions []int
	for i := 0; i < 12; i++ {
		if words[i] == "" {
			missingPositions = append(missingPositions, i)
		}
	}

	// Generate combinations
	indices := make([]int, len(missingPositions))
	startIndex := progress.LastIndex + 1

	for i := startIndex; i < pow(len(wordlist), len(missingPositions)); i++ {
		select {
		case <-ctx.Done():
			return
		default:
			// Convert i to base-2048 for wordlist indices
			num := i
			for j := len(indices) - 1; j >= 0; j-- {
				indices[j] = int(num) % len(wordlist)
				num /= int64(len(wordlist))
			}

			// Fill missing positions with words
			for j, pos := range missingPositions {
				words[pos] = wordlist[indices[j]]
			}

			// Make copy of words slice
			wordsCopy := make([]string, 12)
			copy(wordsCopy, words)

			jobs <- wordsCopy
			atomic.StoreInt64(&progress.LastIndex, int64(i))
		}
	}
}

func checkWallet(mnemonic, targetAddr string) (string, bool) {
	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", false
	}

	path := []uint32{
		uint32(0x8000002C), // Purpose 44'
		uint32(0x800000C3), // Coin type 195'
		uint32(0x80000000), // Account 0'
		uint32(0),          // Change 0
		uint32(0),          // Address index 0
	}

	key := masterKey
	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return "", false
		}
	}

	privateKeyBytes, err := key.ECPrivKey()
	if err != nil {
		return "", false
	}

	privateKey := privateKeyBytes.ToECDSA()
	publicKey := privateKey.Public().(*ecdsa.PublicKey)

	address := generateTronAddress(publicKey)
	return address, address == targetAddr
}

func generateTronAddress(publicKey *ecdsa.PublicKey) string {
	pub := crypto.FromECDSAPub(publicKey)
	hash := crypto.Keccak256(pub[1:])
	address := hash[12:]

	// Add prefix 41
	addressBytes := append([]byte{0x41}, address...)

	// Double SHA256
	h := sha256.New()
	h.Write(addressBytes)
	hash1 := h.Sum(nil)

	h.Reset()
	h.Write(hash1)
	hash2 := h.Sum(nil)

	// Append first 4 bytes of double-sha256 as checksum
	addressBytes = append(addressBytes, hash2[:4]...)

	return Base58Encode(addressBytes)
}

func Base58Encode(input []byte) string {
	const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}

	var result []byte

	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, ALPHABET[mod.Int64()])
	}

	// Add leading zeros
	for _, b := range input {
		if b == 0x00 {
			result = append(result, ALPHABET[0])
		} else {
			break
		}
	}

	// Reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func saveProgressPeriodically(ctx context.Context, progress *Progress) {
	ticker := time.NewTicker(SaveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			saveProgress(progress)
			return
		case <-ticker.C:
			saveProgress(progress)
			fmt.Printf("\rTested combinations: %d", atomic.LoadInt64(&progress.TestedCombos))
		}
	}
}

func saveProgress(progress *Progress) {
	data, _ := json.Marshal(progress)
	os.WriteFile("progress.json", data, 0644)
}

func loadProgress() *Progress {
	data, err := os.ReadFile("progress.json")
	if err != nil {
		return nil
	}
	var progress Progress
	if err := json.Unmarshal(data, &progress); err != nil {
		return nil
	}
	return &progress
}

func pow(x, y int) int64 {
	result := int64(1)
	for i := 0; i < y; i++ {
		result *= int64(x)
	}
	return result
}
