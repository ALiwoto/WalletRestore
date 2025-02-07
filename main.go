package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

func main() {
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
	} else {
		fmt.Printf("You provided %d words. Need exactly 12 words.\n", len(knownWords))
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
