package main

import (
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"math/big"

	"github.com/gin-gonic/gin"
)

// Estructuras
type encrypt_strc struct {
	Public_key string `json:"public_key"`
	Message    string `json:"message"`
}

type decrypt_strc struct {
	Private_key string `json:"private_key"`
	Message     string `json:"message"`
}

// ModExpGoBigInteger calculates modular exponentiation using math/big package.
func ModExpGoBigInteger(base, exponent, modulus int64) int64 {
	return new(big.Int).Mod(new(big.Int).Exp(big.NewInt(base), big.NewInt(exponent), nil), big.NewInt(modulus)).Int64()
}

func rsaEncrypt(publicKey, msg string) string {
	var n, e int64 = extractKey(publicKey)
	var encrypt = ""

	for _, ch := range msg {
		digit := int64(ch)
		numbers_int := ModExpGoBigInteger(digit, e, n)
		numbers := strconv.FormatInt(numbers_int, 10)
		for _, num := range numbers {
			encrypt += string(rune(num + 64))
		}
		encrypt += "&"
	}
	return encrypt
}

func rsaDecrypt(privateKey, text string) string {
	n, d := extractKey(privateKey)
	var decrypt = ""
	var digit = ""
	for _, ch := range text {
		if string(ch) != "&" {
			digit += string(rune(ch - 64))
		} else {
			number, _ := strconv.Atoi(digit)
			decrypt += string(rune(ModExpGoBigInteger(int64(number), d, n)))
			digit = ""
		}
	}
	return decrypt
}

func gcd(x, y int) int {
	var small = 0
	var large = 0

	if x < y {
		small = x
		large = y
	} else {
		small = y
		large = x
	}

	for small != 0 {
		temp := large % small
		large = small
		small = temp
	}
	return large
}

func find_e(z int) int {
	var e = 2
	for e < z {
		if gcd(e, z) == 1 {
			return e
		}
		e += 1
	}
	return 0
}

func find_d(e, z int) int {
	var d = 2
	for d < z {
		if ((d * e) % z) == 1 {
			return d
		}
		d += 1
	}
	return 0
}

func randPrime() int {
	var x, y, n int

	const N = 1000

	nsqrt := math.Sqrt(N)

	var is_prime [N]bool

	for x = 1; float64(x) <= nsqrt; x++ {
		for y = 1; float64(y) <= nsqrt; y++ {
			n = 4*(x*x) + y*y
			if n <= N && (n%12 == 1 || n%12 == 5) {
				is_prime[n] = !is_prime[n]
			}
			n = 3*(x*x) + y*y
			if n <= N && n%12 == 7 {
				is_prime[n] = !is_prime[n]
			}
			n = 3*(x*x) - y*y
			if x > y && n <= N && n%12 == 11 {
				is_prime[n] = !is_prime[n]
			}
		}
	}

	for n = 5; float64(n) <= nsqrt; n++ {
		if is_prime[n] {
			for y = n * n; y < N; y += n * n {
				is_prime[y] = false
			}
		}
	}

	is_prime[2] = true
	is_prime[3] = true

	primes := make([]int, 0, 1270606)
	for x = 0; x < len(is_prime)-1; x++ {
		if is_prime[x] {
			primes = append(primes, x)
		}
	}
	rand.Seed(time.Now().Unix())
	return primes[rand.Intn(len(primes))]
}

func generateKeys() (string, string) {
	var p int = randPrime()
	var q int

	for {
		q = randPrime()
		if q != p {
			break
		}
	}

	var n = int(p) * int(q)
	var z = (int(p) - 1) * (int(q) - 1)

	var e = find_e(z)
	var d = find_d(e, z)

	var sharedPart = strconv.Itoa(n)
	var publicKey = sharedPart + "$" + strconv.Itoa(e)
	var privateKey = sharedPart + "$" + strconv.Itoa(d)

	return publicKey, privateKey
}

func extractKey(key string) (int64, int64) {
	var parts = strings.Split(key, "$")
	var n, _ = strconv.Atoi(parts[0])
	var N, _ = strconv.Atoi(parts[1])

	return int64(n), int64(N)
}

func GenerateKeys(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	var pub, priv = generateKeys()
	c.JSON(http.StatusOK, gin.H{
		"public_key":  pub,
		"private_key": priv})
}

func EncryptMessage(c *gin.Context) {
	var enc encrypt_strc
	c.Header("Access-Control-Allow-Origin", "*")
	c.BindJSON(&enc)
	c.JSON(http.StatusOK, gin.H{"Message": rsaEncrypt(enc.Public_key, enc.Message)})
}

func DecryptMessage(c *gin.Context) {
	var den decrypt_strc
	c.Header("Access-Control-Allow-Origin", "*")
	c.BindJSON(&den)
	c.JSON(http.StatusOK, gin.H{"message": rsaDecrypt(den.Private_key, den.Message)})
}

func OptionMessage(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS, POST, PUT")
}

func main() {
	r := gin.Default()
	r.GET("/api/generate-keys", GenerateKeys)
	r.POST("/api/encrypt", EncryptMessage)
	r.POST("/api/decrypt", DecryptMessage)
	r.Run(":8000")
}
