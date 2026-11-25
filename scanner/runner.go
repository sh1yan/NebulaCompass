package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ErrInterrupted 表示扫描被用户暂停或取消（区别于真正的执行错误）
var ErrInterrupted = errors.New("scan interrupted by user")

// lineEmitter 用于把扫描器输出行回传给任务上下文（SSE + 过程日志）
type lineEmitter func(line string, isErr bool)

type cmdStreamResult struct {
	Stdout string // 仅标准输出（用于解析 XML / 列表结果，不能混入 stderr）
	Stderr string // 仅标准错误
}

// runStream 执行命令，按 \n 与 \r 双分隔读取输出。
// masscan 的进度信息用 \r 刷新在同一行，必须按 \r 也切分才能实时拿到。
func runStream(ctx context.Context, cmd *exec.Cmd, emit lineEmitter) (*cmdStreamResult, error) {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}

	res := &cmdStreamResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	reader := func(r io.Reader, isErr bool) {
		defer wg.Done()
		br := bufio.NewReaderSize(r, 128*1024)
		var lineBuf bytes.Buffer
		flush := func() {
			if lineBuf.Len() == 0 {
				return
			}
			line := strings.TrimRight(lineBuf.String(), "\x00")
			lineBuf.Reset()
			mu.Lock()
			if isErr {
				res.Stderr += line + "\n"
			} else {
				res.Stdout += line + "\n"
			}
			mu.Unlock()
			if emit != nil {
				emit(line, isErr)
			}
		}
		for {
			b, readErr := br.ReadByte()
			if readErr != nil {
				flush()
				return
			}
			if b == '\n' || b == '\r' {
				flush()
				continue
			}
			if lineBuf.Len() < 2<<20 {
				lineBuf.WriteByte(b)
			}
		}
	}

	wg.Add(2)
	go reader(stdoutPipe, false)
	go reader(stderrPipe, true)
	wg.Wait()

	waitErr := cmd.Wait()
	if ctx != nil && ctx.Err() != nil {
		return res, ErrInterrupted
	}
	if waitErr != nil {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = waitErr.Error()
		}
		if len(msg) > 2000 {
			msg = msg[:2000] + "..."
		}
		return res, fmt.Errorf("%v (exit: %v)", msg, waitErr)
	}
	return res, nil
}

// parseArgs 把参数串拆成 argv
func parseArgs(raw string) []string {
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// hasAnyArg 判断 argv 中是否已包含某类参数（支持前缀匹配，如 -sS / -sT / -sn）
func hasAnyArg(args []string, prefixes ...string) bool {
	for _, a := range args {
		for _, p := range prefixes {
			if a == p || strings.HasPrefix(a, p) {
				return true
			}
		}
	}
	return false
}

// dropArgWithValue 移除指定参数及其值（用于避免重复 -oX / -p 等）
func dropArgWithValue(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == flag {
			skipNext = true
			continue
		}
		if strings.HasPrefix(a, flag+"=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// isRoot 判断当前进程是否有 root 权限（-sS 需要）
func isRoot() bool {
	return os.Geteuid() == 0
}
