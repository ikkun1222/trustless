package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/scanner"
)

type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ToolDefinition struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema ToolSchema `json:"inputSchema"`
}

type ToolSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]SchemaProperty `json:"properties"`
	Required   []string                  `json:"required,omitempty"`
}

type SchemaProperty struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type ToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type injectRunArgs struct {
	Secrets  []string `json:"secrets"`
	Command  []string `json:"command"`
	Sanitize bool     `json:"sanitize"`
}

type Server struct {
	backend backend.Backend
}

func NewServer(be backend.Backend) *Server {
	return &Server{backend: be}
}

func (s *Server) Serve(ctx context.Context) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := scanner.Text()

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			resp := Response{
				JSONRPC: "2.0",
				ID:      nil,
				Error: &RPCError{
					Code:    -32700,
					Message: "Parse error",
					Data:    err.Error(),
				},
			}
			if err := enc.Encode(resp); err != nil {
				return fmt.Errorf("encode error response: %w", err)
			}
			continue
		}

		resp := s.dispatch(ctx, &req)
		if resp == nil {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdin scanner error: %w", err)
	}
	return nil
}

func (s *Server) dispatch(ctx context.Context, req *Request) *Response {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "notifications/initialized":
		return nil
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(ctx, req)
	default:
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    -32601,
				Message: fmt.Sprintf("Method not found: %s", req.Method),
			},
		}
	}
}

func (s *Server) handleInitialize(req *Request) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]string{
				"name":    "trustless-mcp",
				"version": "0.1.0",
			},
		},
	}
}

func (s *Server) handleToolsList(req *Request) *Response {
	tools := []ToolDefinition{
		{
			Name:        "resolve_credential",
			Description: "Resolve and return a credential value by key",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"key": {
						Type:        "string",
						Description: "Credential key to resolve",
					},
				},
				Required: []string{"key"},
			},
		},
		{
			Name:        "inject_run",
			Description: "Run a command with credential values injected as environment variables, returning stdout/stderr/exit code. Credentials are redacted from output.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"secrets": {
						Type:        "array",
						Description: "Credential specs (format: KEY or KEY:ENVNAME)",
					},
					"command": {
						Type:        "array",
						Description: "Command and arguments to run",
					},
					"sanitize": {
						Type:        "boolean",
						Description: "Enable output sanitization (default: true)",
					},
				},
				Required: []string{"secrets", "command"},
			},
		},
		{
			Name:        "list_credentials",
			Description: "List all available credential keys in the store",
			InputSchema: ToolSchema{
				Type:       "object",
				Properties: map[string]SchemaProperty{},
			},
		},
	}

	return &Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
}

func (s *Server) handleToolsCall(ctx context.Context, req *Request) *Response {
	paramsJSON, err := json.Marshal(req.Params)
	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid params",
				Data:    err.Error(),
			},
		}
	}

	var callParams CallToolParams
	if err := json.Unmarshal(paramsJSON, &callParams); err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid params",
				Data:    err.Error(),
			},
		}
	}

	switch callParams.Name {
	case "resolve_credential":
		return s.callResolveCredential(ctx, req.ID, callParams.Arguments)
	case "inject_run":
		return s.callInjectRun(ctx, req.ID, callParams.Arguments)
	case "list_credentials":
		return s.callListCredentials(ctx, req.ID)
	default:
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    -32602,
				Message: fmt.Sprintf("Unknown tool: %s", callParams.Name),
			},
		}
	}
}

func (s *Server) callResolveCredential(ctx context.Context, id interface{}, args map[string]interface{}) *Response {
	key, ok := args["key"].(string)
	if !ok || key == "" {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32602,
				Message: "Missing or invalid required argument: key",
			},
		}
	}

	val, err := s.backend.Resolve(ctx, key)
	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32000,
				Message: fmt.Sprintf("Failed to resolve credential: %v", err),
			},
		}
	}

	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolResult{
			Content: []ToolContent{
				{
					Type: "text",
					Text: val,
				},
			},
		},
	}
}

func (s *Server) callInjectRun(ctx context.Context, id interface{}, args map[string]interface{}) *Response {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid arguments",
				Data:    err.Error(),
			},
		}
	}

	var runArgs injectRunArgs
	if err := json.Unmarshal(argsJSON, &runArgs); err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32602,
				Message: "Invalid arguments",
				Data:    err.Error(),
			},
		}
	}

	if len(runArgs.Secrets) == 0 {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32602,
				Message: "Missing required argument: secrets",
			},
		}
	}
	if len(runArgs.Command) == 0 {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32602,
				Message: "Missing required argument: command",
			},
		}
	}

	env := os.Environ()
	var credValues []string

	for _, spec := range runArgs.Secrets {
		var secretKey, envName string
		if colon := strings.Index(spec, ":"); colon >= 0 {
			secretKey = spec[:colon]
			envName = spec[colon+1:]
		} else {
			secretKey = spec
			last := spec
			if idx := strings.LastIndex(spec, "/"); idx >= 0 {
				last = spec[idx+1:]
			}
			envName = strings.ToUpper(strings.ReplaceAll(last, "-", "_"))
		}

		val, err := s.backend.Resolve(ctx, secretKey)
		if err != nil {
			return &Response{
				JSONRPC: "2.0",
				ID:      id,
				Error: &RPCError{
					Code:    -32000,
					Message: fmt.Sprintf("Failed to resolve credential %q: %v", secretKey, err),
				},
			}
		}
		env = append(env, envName+"="+val)
		credValues = append(credValues, val)
	}

	cmd := exec.CommandContext(ctx, runArgs.Command[0], runArgs.Command[1:]...)
	cmd.Env = env

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return &Response{
				JSONRPC: "2.0",
				ID:      id,
				Error: &RPCError{
					Code:    -32000,
					Message: fmt.Sprintf("Failed to run command: %v", err),
				},
			}
		}
	}

	stdout := stdoutBuf.Bytes()
	stderr := stderrBuf.Bytes()

	if runArgs.Sanitize {
		sc := scanner.New()
		stdout = sc.ScanWithValues(stdout, credValues)
		stderr = sc.ScanWithValues(stderr, credValues)
	}

	result := map[string]interface{}{
		"exit_code": exitCode,
		"stdout":    string(stdout),
		"stderr":    string(stderr),
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32000,
				Message: fmt.Sprintf("Failed to marshal result: %v", err),
			},
		}
	}

	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolResult{
			Content: []ToolContent{
				{
					Type: "text",
					Text: string(resultJSON),
				},
			},
			IsError: exitCode != 0,
		},
	}
}

func (s *Server) callListCredentials(ctx context.Context, id interface{}) *Response {
	entries, err := s.backend.List(ctx)
	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32000,
				Message: fmt.Sprintf("Failed to list credentials: %v", err),
			},
		}
	}

	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.Key)
	}

	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			ID:      id,
			Error: &RPCError{
				Code:    -32000,
				Message: fmt.Sprintf("Failed to marshal result: %v", err),
			},
		}
	}

	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolResult{
			Content: []ToolContent{
				{
					Type: "text",
					Text: string(keysJSON),
				},
			},
		},
	}
}

func envVarName(key string) string {
	last := key
	if idx := strings.LastIndex(key, "/"); idx >= 0 {
		last = key[idx+1:]
	}
	return strings.ToUpper(strings.ReplaceAll(last, "-", "_"))
}
