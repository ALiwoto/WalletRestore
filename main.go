package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"runtime"

	"github.com/ALiwoto/ssg/ssg"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

func init() {
	// Set it to use all available CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())
}

const (
	SaveInterval               = 10 * time.Second
	AllPositionsAreKnown       = true
	EstimateChecksPerGoroutine = 600
)

type Progress struct {
	LastIndex      int64    `json:"last_index"`
	TestedCombos   int64    `json:"tested_combinations"`
	KnownWords     []string `json:"known_words"`
	KnownPositions []int    `json:"known_positions"`
}

type WorkerInfo struct {
	Ctx              context.Context
	WorkersWaitGroup *sync.WaitGroup
	WalletTargetAddr []byte
	RestoreProgress  *Progress
	WorkerId         int64
	TotalJobs        int64
	TotalGoroutines  int64
}

var (
	NoProgress        = false
	MaxGoroutines     = 4 // Adjust based on your CPU
	TotalWordsCount   = 12
	TotalCombinations = int64(0)
)

func main() {
	fmt.Printf("Number of CPUs available to us: %d\n", runtime.NumCPU())

	for _, currentArg := range os.Args {
		if currentArg == "--no-progress" {
			NoProgress = true
		} else if strings.HasPrefix(currentArg, "--cores:") {
			myStrs := strings.Split(currentArg, ":")
			if len(myStrs) < 2 {
				continue
			}
			myValue := ssg.ToInt(myStrs[1])
			if myValue > 0 {
				MaxGoroutines = myValue
			}
		}

	}
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

	fmt.Println("Using " + ssg.ToBase10(MaxGoroutines) + " Goroutines.")
	fmt.Println("Please write as many words as you have (space-separated):")
	knownWordsInput, _ := reader.ReadString('\n')
	if knownWordsInput == "cancel" {
		fmt.Println("Cancelling the operation as per user request")
		return
	}

	knownWords := strings.Fields(strings.TrimSpace(knownWordsInput))

	fmt.Println("Please give me the wallet address you would like to match:")
	targetAddr, _ := reader.ReadString('\n')
	targetAddr = strings.TrimSpace(targetAddr)
	if targetAddr == "cancel" {
		fmt.Println("Cancelling the operation as per user request")
		return
	}

	decodedTargetAddress := base58.Decode(targetAddr)

	if len(knownWords) == 12 {
		mnemonic := strings.Join(knownWords, " ")
		if address, ok := checkWallet(mnemonic, decodedTargetAddress); ok {
			fmt.Printf("Found match!\nAddress: %s\nMnemonic: %s\n", base58.Encode(address), mnemonic)
		} else {
			fmt.Printf("No match found.\nGenerated address: %s\n", base58.Encode(address))
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
	// jobs := make(chan []string, MaxGoroutines)
	var wg sync.WaitGroup

	fmt.Println("Start timestamp: " + ssg.ToBase10(time.Now().Unix()))

	// Generate and test combinations
	missingCount := TotalWordsCount - len(knownWords)
	TotalCombinations = int64(math.Pow(float64(len(wordlist)), float64(missingCount)))
	estimateChecksPerSeconds := int64(EstimateChecksPerGoroutine * MaxGoroutines)

	fmt.Printf("Total combinations to test: %d\n", TotalCombinations)
	fmt.Printf("Estimated time: %v (at "+
		ssg.ToBase10(estimateChecksPerSeconds)+" checks/sec)\n",
		time.Duration(TotalCombinations/estimateChecksPerSeconds)*time.Second,
	)

	// Start workers
	for i := 0; i < MaxGoroutines; i++ {
		wg.Add(1)
		go worker(&WorkerInfo{
			Ctx:              ctx,
			WorkersWaitGroup: &wg,
			WalletTargetAddr: decodedTargetAddress,
			RestoreProgress:  progress,
			WorkerId:         int64(i),
			TotalJobs:        TotalCombinations,
			TotalGoroutines:  int64(MaxGoroutines),
		})
	}

	// Start progress saver
	go saveProgressPeriodically(ctx, progress)

	// generateCombinations(ctx, wordlist, progress, jobs)

	// close(jobs)
	wg.Wait()

	fmt.Printf("\nTested %d combinations\n", atomic.LoadInt64(&progress.TestedCombos))
	fmt.Println("Finish timestamp: " + ssg.ToBase10(time.Now().Unix()))
}

func worker(info *WorkerInfo) {
	defer info.WorkersWaitGroup.Done()

	words := make([]string, TotalWordsCount)

	// Fill known words
	for i, word := range info.RestoreProgress.KnownWords {
		words[info.RestoreProgress.KnownPositions[i]] = word
	}

	// Get positions that need to be filled
	var missingPositions []int
	for i := 0; i < TotalWordsCount; i++ {
		if words[i] == "" {
			missingPositions = append(missingPositions, i)
		}
	}

	indices := make([]int, len(missingPositions))
	var currentTestedCombos int
	maxCurrentCombo := min(MaxGoroutines*100, 5000)

	// Each worker calculates its own range of jobs
	jobsPerWorker := info.TotalJobs / info.TotalGoroutines
	startIndex := info.WorkerId * jobsPerWorker
	endIndex := startIndex + jobsPerWorker

	// Last worker takes any remaining jobs
	if info.WorkerId == info.TotalJobs-1 {
		endIndex = info.TotalJobs
	}

	// Process own range of jobs
	for currentIndex := startIndex; currentIndex < endIndex; currentIndex++ {
		select {
		case <-info.Ctx.Done():
			return
		default:
			num := currentIndex
			for j := len(indices) - 1; j >= 0; j-- {
				indices[j] = int(num) % len(bip39.GetWordList())
				num /= int64(len(bip39.GetWordList()))
			}

			// Fill missing positions with words
			for j, pos := range missingPositions {
				words[pos] = bip39.GetWordList()[indices[j]]
			}

			if !containsRepeated(words) {
				if address, ok := checkWallet(strings.Join(words, " "), info.WalletTargetAddr); ok {
					fmt.Printf("\nFOUND MATCH!\nAddress: %s\nWords: %s\n", base58.Encode(address), strings.Join(words, " "))
					fmt.Println("Finish timestamp: " + ssg.ToBase10(time.Now().Unix()))
					os.Exit(0)
				}
			}

			currentTestedCombos++
			if (currentTestedCombos % maxCurrentCombo) == 0 {
				atomic.AddInt64(&info.RestoreProgress.TestedCombos, int64(currentTestedCombos))
				currentTestedCombos = 0
			}
		}
	}
}

func OldGenerateCombinations(ctx context.Context, wordlist []string, progress *Progress, jobs chan<- []string) {
	words := make([]string, TotalWordsCount)

	// Fill known words
	for i, word := range progress.KnownWords {
		words[progress.KnownPositions[i]] = word
	}

	// Get positions that need to be filled
	var missingPositions []int
	for i := 0; i < TotalWordsCount; i++ {
		if words[i] == "" {
			missingPositions = append(missingPositions, i)
		}
	}

	// Generate combinations
	indices := make([]int, len(missingPositions))
	startIndex := progress.LastIndex + 1

	for i := startIndex; i < TotalCombinations; i++ {
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
			wordsCopy := make([]string, TotalWordsCount)
			copy(wordsCopy, words)

			jobs <- wordsCopy
			atomic.StoreInt64(&progress.LastIndex, int64(i))
		}
	}
}

func CreateAddressFromSeeds(seeds string) []byte {
	seed := bip39.NewSeed(seeds, "")
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil
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
			return nil
		}
	}

	privateKeyBytes, err := key.ECPrivKey()
	if err != nil {
		return nil
	}

	privateKey := privateKeyBytes.ToECDSA()
	publicKey := privateKey.Public().(*ecdsa.PublicKey)

	return generateTronAddress(publicKey)
}

func checkWallet(mnemonic string, targetAddr []byte) ([]byte, bool) {
	address := CreateAddressFromSeeds(mnemonic)

	return address, bytes.Equal(address, targetAddr)
}

func generateTronAddress(publicKey *ecdsa.PublicKey) []byte {
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

	return addressBytes
}

func Base58Encode(input []byte) string {
	return base58.Encode(input)
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
	if NoProgress {
		return
	}
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

func containsRepeated(words []string) bool {
	wordMap := make(map[string]bool)
	for _, word := range words {
		if _, exists := wordMap[word]; exists {
			return true
		}
		wordMap[word] = true
	}
	return false
}
