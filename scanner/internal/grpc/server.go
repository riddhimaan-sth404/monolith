package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/edr/scanner/internal/config"
	"github.com/edr/scanner/internal/scanner"
	pb "github.com/edr/scanner/internal/grpc/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	cfg    *config.Config
	engine *scanner.ScannerEngine
	server *grpc.Server
}

func NewServer(cfg *config.Config, engine *scanner.ScannerEngine) *Server {
	return &Server{
		cfg:    cfg,
		engine: engine,
	}
}

func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.cfg.GRPC.Listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.server = grpc.NewServer(
		grpc.MaxRecvMsgSize(4 * 1024 * 1024), // 4MB max message (scan requests are tiny)
	)

	// Register scanner service
	pb.RegisterScannerServiceServer(s.server, &scannerService{
		engine: s.engine,
	})

	reflection.Register(s.server)

	slog.Info("gRPC server listening", "addr", s.cfg.GRPC.Listen)
	return s.server.Serve(lis)
}

func (s *Server) Stop() {
	slog.Info("stopping gRPC server")
	if s.server != nil {
		s.server.GracefulStop()
	}
}

type scannerService struct {
	pb.UnimplementedScannerServiceServer
	engine *scanner.ScannerEngine
}

func (svc *scannerService) StartScan(ctx context.Context, req *pb.ScanRequest) (*pb.ScanStatusMessage, error) {
	slog.Info("gRPC StartScan called", "scan_type", req.ScanType, "paths", req.Paths)

	// req.ScanType is a string; compare with literal values
	switch req.ScanType {
	case "quick":
		svc.engine.StartQuickScan()
	case "full":
		svc.engine.StartFullScan()
	default:
		for _, path := range req.Paths {
			svc.engine.EnqueueScan(path)
		}
	}

	status := "running"
	if svc.engine.ActiveJobs() == 0 {
		status = "completed"
	}

	return &pb.ScanStatusMessage{
		Status:  status,
		Message: "Scan started",
	}, nil
}

func (svc *scannerService) StopScan(ctx context.Context, req *pb.StopRequest) (*pb.ScanStatusMessage, error) {
	slog.Info("gRPC StopScan called", "scan_id", req.ScanId)

	svc.engine.Stop()

	return &pb.ScanStatusMessage{
		Status:  "cancelled",
		Message: "Scan stopped",
	}, nil
}

func (svc *scannerService) GetScanStatus(ctx context.Context, req *pb.StatusRequest) (*pb.ScanStatusMessage, error) {
	activeJobs := svc.engine.ActiveJobs()
	status := "running"
	if activeJobs == 0 {
		status = "completed"
	}

	return &pb.ScanStatusMessage{
		Status:  status,
		Message: fmt.Sprintf("%d active jobs", activeJobs),
	}, nil
}

func (svc *scannerService) StreamScanResults(req *pb.StatusRequest, stream pb.ScannerServiceStreamServer) error {
	slog.Info("gRPC StreamScanResults called")

	resultsCh := svc.engine.SubscribeResults()
	defer svc.engine.UnsubscribeResults(resultsCh)

	for {
		select {
		case result, ok := <-resultsCh:
			if !ok {
				return nil
			}

			slog.Debug("streaming scan result", "path", result.FilePath, "verdict", result.Verdict)

			scanResult := &pb.ScanResult{
				FilePath:    result.FilePath,
				FileName:    result.FileName,
				Verdict:     result.Verdict,
				Score:       result.Score,
				Quarantined: result.Quarantined,
			}

			if err := stream.Send(scanResult); err != nil {
				return err
			}

		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (svc *scannerService) ReportScanSummary(ctx context.Context, req *pb.ScanSummary) (*pb.ScanAck, error) {
	slog.Info("gRPC ReportScanSummary called",
		"total", req.TotalFiles,
		"malicious", req.MaliciousFiles,
		"suspicious", req.SuspiciousFiles,
	)

	return &pb.ScanAck{
		Received: true,
	}, nil
}

func (svc *scannerService) ScannerHealth(ctx context.Context, req *pb.Empty) (*pb.ScannerHealthResponse, error) {
	return &pb.ScannerHealthResponse{
		Healthy:       true,
		Version:       "1.0.0",
		UptimeSeconds: uint64(time.Now().Unix()),
		ActiveWorkers: uint32(svc.engine.ActiveJobs()),
	}, nil
}
