package services

import (
	"golang.org/x/crypto/bcrypt"
)

// HashingResult holds the outcome of a hashing job.
type HashingResult struct {
	Hash string
	Err  error
}

// HashingJob represents a password to be hashed.
type HashingJob struct {
	Password   string
	ResultChan chan<- HashingResult
}

// Hasher manages a pool of workers for CPU-intensive hashing.
type Hasher struct {
	jobChan    chan HashingJob
	bcryptCost int
}

// NewHasher creates and starts a new Hasher service.
func NewHasher(numWorkers int, cost int) *Hasher {
	h := &Hasher{
		jobChan:    make(chan HashingJob),
		bcryptCost: cost,
	}

	// Start the background workers
	for i := 0; i < numWorkers; i++ {
		go h.worker()
	}

	return h
}

// worker is a background goroutine that processes hashing jobs.
func (h *Hasher) worker() {
	for job := range h.jobChan {
		hash, err := bcrypt.GenerateFromPassword([]byte(job.Password), h.bcryptCost)
		job.ResultChan <- HashingResult{
			Hash: string(hash),
			Err:  err,
		}
	}
}

// GenerateHash sends a password to the worker pool and waits for the result.
func (h *Hasher) GenerateHash(password string) (string, error) {
	resultChan := make(chan HashingResult)
	h.jobChan <- HashingJob{
		Password:   password,
		ResultChan: resultChan,
	}

	result := <-resultChan
	return result.Hash, result.Err
}