package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
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

	// If we have exactly 12 words, try that combination
	if len(knownWords) == 12 {
		mnemonic := strings.Join(knownWords, " ")
		if address, ok := checkWallet(mnemonic, targetAddr); ok {
			fmt.Printf("Found match!\nAddress: %s\nMnemonic: %s\n", address, mnemonic)
		} else {
			fmt.Println("No match found for these words.")
		}
	} else {
		fmt.Printf("You provided %d words. Need exactly 12 words.\n", len(knownWords))
	}
}

func checkWallet(mnemonic, targetAddr string) (string, bool) {
	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Generate master key
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", false
	}

	// Derive purpose
	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44)
	if err != nil {
		return "", false
	}

	// Derive coin type (195 for TRON)
	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 195)
	if err != nil {
		return "", false
	}

	// Derive account
	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", false
	}

	// Derive change
	change, err := account.Derive(0)
	if err != nil {
		return "", false
	}

	// Derive address index
	address, err := change.Derive(0)
	if err != nil {
		return "", false
	}

	// Get private key
	privateKeyBytes, err := address.ECPrivKey()
	if err != nil {
		return "", false
	}

	privateKey := privateKeyBytes.ToECDSA()
	publicKey := privateKey.Public().(*ecdsa.PublicKey)

	// Generate TRON address
	address41 := generateTronAddress(publicKey)

	return address41, address41 == targetAddr
}

func generateTronAddress(publicKey *ecdsa.PublicKey) string {
	pub := crypto.FromECDSAPub(publicKey)
	hash := crypto.Keccak256(pub[1:])
	address := hash[12:]

	// Add prefix 41
	addressHex := fmt.Sprintf("41%x", address)

	// Convert to base58
	decoded, _ := hex.DecodeString(addressHex)
	base58Address := Base58EncodeAddr(decoded)

	return base58Address
}

func Base58EncodeAddr(input []byte) string {
	const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	var result []byte

	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}

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
