package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Output represents a transaction output in the signing request
type Output struct {
	ParticipantCode      string `json:"participant_code"`
	Amount               string `json:"amount"`
	ZeroHashID           string `json:"zero_hash_id"`
	SourceDerivationPath string `json:"source_derivation_path"`
	DestinationAddress   string `json:"destination_address"`
	PlatformCode         string `json:"platform_code"`
	WithdrawalRequestID  string `json:"withdrawal_request_id"`
}

// SignRequest represents the request structure for the signing endpoint
type SignRequest struct {
	IdempotencyKey  string   `json:"idempotencykey"`
	Description     string   `json:"description"`
	Currency        string   `json:"currency"`
	FeeLevel        string   `json:"fee_level"`
	TransactionType string   `json:"transaction_type"`
	Outputs         []Output `json:"outputs"`
	ReceiveCount    int      `json:"receive_count"`
	DryRun          bool     `json:"dry_run"`
}

// SignResponse represents the response from the signing endpoint
type SignResponse struct {
	// Add the appropriate fields based on the actual response
	Success bool   `json:"success"`
	Message string `json:"message"`
	// Add any other fields that might be in the response
}

// CreateSolanaSignRequest creates a new SignRequest with the provided parameters
func CreateSolanaSignRequest(
	idempotencyKey string,
	description string,
	currency string,
	feeLevel string,
	transactionType string,
	outputs []Output,
	receiveCount int,
) SignRequest {
	return SignRequest{
		IdempotencyKey:  idempotencyKey,
		Description:     description,
		Currency:        currency,
		FeeLevel:        feeLevel,
		TransactionType: transactionType,
		Outputs:         outputs,
		ReceiveCount:    receiveCount,
		DryRun:          true,
	}
}

// SignTransaction sends a request to the sign endpoint
func SignTransaction(ctx context.Context, baseURL string, request SignRequest) (*SignResponse, error) {
	// Start timing the request
	startTime := time.Now()
	txID := request.IdempotencyKey

	slog.Info("Signing transaction", "tx_id", txID, "currency", request.Currency)

	// Convert request to JSON
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	url := fmt.Sprintf("%s/v1/sign", baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Sign request failed", "tx_id", txID, "error", err)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check if response is successful
	if resp.StatusCode != http.StatusOK {
		slog.Error("Sign request failed", "tx_id", txID, "status", resp.StatusCode)
		return nil, fmt.Errorf("sign request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response SignResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	slog.Info("Transaction signed", "tx_id", txID, "duration_ms", time.Since(startTime).Milliseconds())
	return &response, nil
}

// EntityInfo represents entity information in webhook transaction data
type EntityInfo struct {
	ID      *string `json:"id"`
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	SubType string  `json:"subType"`
}

// AmountInfo represents amount information in webhook transaction data
type AmountInfo struct {
	Amount          *float64 `json:"amount"`
	RequestedAmount *float64 `json:"requestedAmount"`
}

// FeeInfo represents fee information in webhook transaction data
type FeeInfo struct {
	// Add fee-related fields if needed
}

// BlockInfo represents blockchain information in webhook transaction data
type BlockInfo struct {
	// Add blockchain-related fields if needed
}

// SignatureInfo represents signature information
type SignatureInfo struct {
	R       string `json:"r"`
	S       string `json:"s"`
	V       int    `json:"v"`
	FullSig string `json:"fullSig"`
}

// SignedMessage represents a signed message in the transaction
type SignedMessage struct {
	DerivationPath []int         `json:"derivationPath"`
	Algorithm      string        `json:"algorithm"`
	PublicKey      string        `json:"publicKey"`
	Signature      SignatureInfo `json:"signature"`
	Content        string        `json:"content"`
}

// MessageData represents raw message data in extra parameters
type MessageData struct {
	Content        string `json:"content"`
	DerivationPath []int  `json:"derivationPath"`
}

// RawMessageData represents raw message data in extra parameters
type RawMessageData struct {
	Messages  []MessageData `json:"messages"`
	Algorithm string        `json:"algorithm"`
}

// ExtraParameters represents additional parameters for the transaction
type ExtraParameters struct {
	RawMessageData RawMessageData `json:"rawMessageData"`
}

// TransactionData represents the transaction data in the webhook payload
type TransactionData struct {
	ID                     string          `json:"id"`
	CreatedAt              int64           `json:"createdAt"`
	LastUpdated            int64           `json:"lastUpdated"`
	AssetID                *string         `json:"assetId"`
	Source                 EntityInfo      `json:"source"`
	Destination            EntityInfo      `json:"destination"`
	Amount                 float64         `json:"amount"`
	SourceAddress          string          `json:"sourceAddress"`
	DestinationAddress     string          `json:"destinationAddress"`
	DestinationAddressDesc string          `json:"destinationAddressDescription"`
	DestinationTag         string          `json:"destinationTag"`
	Status                 string          `json:"status"`
	TxHash                 string          `json:"txHash"`
	SubStatus              string          `json:"subStatus"`
	SignedBy               []string        `json:"signedBy"`
	CreatedBy              string          `json:"createdBy"`
	RejectedBy             string          `json:"rejectedBy"`
	AmountUSD              *float64        `json:"amountUSD"`
	AddressType            string          `json:"addressType"`
	Note                   string          `json:"note"`
	ExchangeTxId           string          `json:"exchangeTxId"`
	RequestedAmount        float64         `json:"requestedAmount"`
	FeeCurrency            string          `json:"feeCurrency"`
	Operation              string          `json:"operation"`
	CustomerRefId          *string         `json:"customerRefId"`
	AmountInfo             AmountInfo      `json:"amountInfo"`
	FeeInfo                FeeInfo         `json:"feeInfo"`
	Destinations           []interface{}   `json:"destinations"`
	ExternalTxId           *string         `json:"externalTxId"`
	BlockInfo              BlockInfo       `json:"blockInfo"`
	SignedMessages         []SignedMessage `json:"signedMessages"`
	ExtraParameters        ExtraParameters `json:"extraParameters"`
}

// WebhookEvent represents the webhook event payload
type WebhookEvent struct {
	EventType   string          `json:"eventType"`
	CreatedAt   int64           `json:"createdAt"`
	ID          string          `json:"id"`
	WorkspaceID string          `json:"workspaceId"`
	Data        TransactionData `json:"data"`
}

// WebhookResponse represents the response from the webhook endpoint
type WebhookResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SendWebhookEvent sends a webhook event to the specified endpoint
func SendWebhookEvent(ctx context.Context, baseURL string, event WebhookEvent) (*WebhookResponse, error) {
	// Start timing the request
	startTime := time.Now()
	txID := event.Data.ID

	slog.Info("Sending webhook", "tx_id", txID, "event_type", event.EventType, "status", event.Data.Status)

	// Convert event to JSON
	jsonData, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal webhook event: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	url := fmt.Sprintf("%s/webhook/v2/events", baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Webhook send failed", "tx_id", txID, "error", err)
		return nil, fmt.Errorf("webhook HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read webhook response: %w", err)
	}

	// Check if response is successful
	if resp.StatusCode != http.StatusOK {
		slog.Error("Webhook send failed", "tx_id", txID, "status", resp.StatusCode)
		return nil, fmt.Errorf("webhook request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response WebhookResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse webhook response: %w", err)
	}

	slog.Info("Webhook sent", "tx_id", txID, "duration_ms", time.Since(startTime).Milliseconds())
	return &response, nil
}

// DockerLogState represents the deserialized JSON from the docker log lines
type DockerLogState struct {
	Time            string   `json:"time"`
	Level           string   `json:"level"`
	Msg             string   `json:"msg"`
	State           string   `json:"state"`
	TraceID         string   `json:"trace_id"`
	IdempotencyKey  string   `json:"idempotency_key"`
	TimeUntilExpiry string   `json:"time_until_expiry"`
	Attempts        int      `json:"attempts"`
	SignTxIDs       []string `json:"signTxIDs"`
	TxHash          string   `json:"txHash"`
}

// MonitorDockerLogs watches the docker logs for a specific transaction completion
func MonitorDockerLogs(ctx context.Context, containerName string, txUUID string, timeout time.Duration) (*DockerLogState, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Start timing for log discovery
	logStartTime := time.Now()
	slog.Info("Starting to monitor docker logs", "container", containerName, "tx_id", txUUID)

	// Create command to follow docker logs - try appending -1 to container name if needed
	// This handles Docker Compose naming format (service-name-1)
	cmd := exec.CommandContext(ctx, "docker", "logs", "--follow", containerName+"-1")

	// Test if container exists with the -1 suffix
	testCmd := exec.Command("docker", "ps", "--filter", "name="+containerName+"-1", "--format", "{{.Names}}")
	testOutput, err := testCmd.Output()
	if err != nil || len(testOutput) == 0 {
		// Fall back to original container name
		cmd = exec.CommandContext(ctx, "docker", "logs", "--follow", containerName)
		slog.Info("Container with -1 suffix not found, using original name", "container", containerName)
	} else {
		slog.Info("Using container with -1 suffix", "container", containerName+"-1")
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start docker logs command: %w", err)
	}

	// Use bufio.Scanner for more reliable line reading
	scanner := bufio.NewScanner(stdout)

	// Increase scanner buffer size for long log lines
	const maxCapacity = 512 * 1024 // 512KB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	// Setup a done channel to signal when we've found the desired log
	done := make(chan struct{})
	var logState *DockerLogState
	var scanErr error
	var logFoundTime time.Time

	// Start scanning in a goroutine
	go func() {
		defer close(done)

		for scanner.Scan() {
			line := scanner.Text()

			// Look for relevant log lines
			if strings.Contains(line, `"msg":"state transition"`) &&
				strings.Contains(line, `"state":"Terminated"`) {

				// The log line might not parse as valid JSON due to non-printable characters
				// Try to clean it up
				cleanLine := strings.TrimSpace(line)

				var state DockerLogState
				if err := json.Unmarshal([]byte(cleanLine), &state); err != nil {
					slog.Error("Failed to parse log JSON", "error", err, "line", cleanLine)
					continue
				}

				// Check if the idempotencyKey contains our UUID
				// Note that in the logs, the idempotencyKey might have a suffix like ".358775311"
				if strings.Contains(state.IdempotencyKey, txUUID) {
					logFoundTime = time.Now()
					searchDuration := logFoundTime.Sub(logStartTime)
					slog.Info("Found matching transaction",
						"txUUID", txUUID,
						"idempotencyKey", state.IdempotencyKey,
						"search_duration_ms", searchDuration.Milliseconds())
					logState = &state
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			scanErr = err
		}
	}()

	// Wait for either context cancellation or finding the log
	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timeout waiting for transaction completion")
		}
		return nil, ctx.Err()

	case <-done:
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		if scanErr != nil {
			return nil, fmt.Errorf("error scanning logs: %w", scanErr)
		}
		if logState == nil {
			return nil, fmt.Errorf("log scanning completed but target log not found")
		}
		return logState, nil
	}
}

// Example usage of the SignTransaction function
func main() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(jsonHandler))

	baseURL := "http://localhost:9102"
	ctx := context.Background()

	// Variables to store aggregated timing data
	numTransactions := 50
	var totalTxDurations []time.Duration
	var signDurations []time.Duration
	var logMonitorDurations []time.Duration
	var blockchainProcessingDurations []time.Duration

	// Run specified number of transactions
	for i := 0; i < numTransactions; i++ {
		runID := i + 1
		slog.Info("Starting transaction batch", "tx_number", runID, "of", numTransactions)

		// Start the overall transaction timing
		txStartTime := time.Now()

		// Generate a unique transaction ID (UUID)
		txUUID := uuid.New().String()
		slog.Info("Starting transaction flow", "tx_id", txUUID, "tx_number", runID)

		outputs := []Output{
			{
				ParticipantCode:      "ZHH1NA",
				Amount:               "179400",
				ZeroHashID:           txUUID,
				SourceDerivationPath: "59",
				DestinationAddress:   "9WotpYvQ9YwMKhbCUKnJGWuJjaZMvqfiTMXebUTTQURb",
				PlatformCode:         "H552SV",
				WithdrawalRequestID:  txUUID,
			},
		}

		// Create the request using the helper function
		request := CreateSolanaSignRequest(
			txUUID,
			fmt.Sprintf("WITHDRAWAL:%s", txUUID),
			"SOL",
			"HIGH",
			"WITHDRAWAL",
			outputs,
			10,
		)

		// PHASE 1: Call the SignTransaction function
		signStartTime := time.Now()
		_, err := SignTransaction(ctx, baseURL, request)
		if err != nil {
			slog.Error("Transaction flow failed", "tx_id", txUUID, "error", err, "tx_number", runID)
			continue
		}
		signDuration := time.Since(signStartTime)
		signDurations = append(signDurations, signDuration)

		// PHASE 2: Monitor docker logs for transaction completion
		logMonitorStartTime := time.Now()
		containerName := "blockchain-solana-service-solana-signer"
		logState, err := MonitorDockerLogs(ctx, containerName, txUUID, 5*time.Minute)
		if err != nil {
			slog.Error("Failed to monitor transaction completion", "tx_id", txUUID, "error", err, "tx_number", runID)
			continue
		}
		logMonitorDuration := time.Since(logMonitorStartTime)
		logMonitorDurations = append(logMonitorDurations, logMonitorDuration)

		// Calculate total transaction duration
		totalDuration := time.Since(txStartTime)
		totalTxDurations = append(totalTxDurations, totalDuration)
		blockchainProcessingDurations = append(blockchainProcessingDurations, totalDuration-signDuration)

		// Transaction completed successfully
		slog.Info("Transaction completed successfully",
			"tx_id", txUUID,
			"state", logState.State,
			"txHash", logState.TxHash,
			"tx_number", runID,
			"total_duration_ms", totalDuration.Milliseconds(),
			"sign_duration_ms", signDuration.Milliseconds(),
			"log_monitor_duration_ms", logMonitorDuration.Milliseconds(),
			"blockchain_processing_ms", (totalDuration - signDuration).Milliseconds())
	}

	// Calculate and print average times
	if len(totalTxDurations) > 0 {
		var totalAvg, signAvg, logAvg, blockchainAvg int64

		for _, d := range totalTxDurations {
			totalAvg += d.Milliseconds()
		}
		totalAvg /= int64(len(totalTxDurations))

		for _, d := range signDurations {
			signAvg += d.Milliseconds()
		}
		signAvg /= int64(len(signDurations))

		for _, d := range logMonitorDurations {
			logAvg += d.Milliseconds()
		}
		logAvg /= int64(len(logMonitorDurations))

		for _, d := range blockchainProcessingDurations {
			blockchainAvg += d.Milliseconds()
		}
		blockchainAvg /= int64(len(blockchainProcessingDurations))

		slog.Info("Transaction timing summary",
			"transactions_completed", len(totalTxDurations),
			"avg_total_duration_ms", totalAvg,
			"avg_sign_duration_ms", signAvg,
			"avg_log_monitor_duration_ms", logAvg,
			"avg_blockchain_processing_ms", blockchainAvg)
	} else {
		slog.Error("No transactions completed successfully")
	}
}
