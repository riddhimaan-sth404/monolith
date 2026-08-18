// Package pb provides protobuf-derived Go types for the scanner gRPC service.
package pb

import (
	"context"
	"time"

	"google.golang.org/grpc"
)

// --- Enums ---

type ScanType int32
type ScanStatus int32

const (
	ScanTypeUnspecified ScanType = 0
	ScanTypeQuick       ScanType = 1
	ScanTypeFull        ScanType = 2
	ScanTypeCustom      ScanType = 3

	ScanStatusUnspecified ScanStatus = 0
	ScanStatusPending     ScanStatus = 1
	ScanStatusRunning     ScanStatus = 2
	ScanStatusCompleted   ScanStatus = 3
	ScanStatusFailed      ScanStatus = 4
	ScanStatusCancelled   ScanStatus = 5
)

func (s ScanStatus) String() string {
	switch s {
	case ScanStatusPending:
		return "pending"
	case ScanStatusRunning:
		return "running"
	case ScanStatusCompleted:
		return "completed"
	case ScanStatusFailed:
		return "failed"
	case ScanStatusCancelled:
		return "cancelled"
	default:
		return "unspecified"
	}
}

// --- Messages ---

type ScanRequest struct {
	Id                  string
	ScanType            string
	Paths               []string
	YaraScan            bool
	HashCheck           bool
	SignatureCheck      bool
	QuarantineMalicious bool
	Priority            uint32
}

type ScanStatusMessage struct {
	ScanId        string
	Status        string
	ScanType      string
	StartedAt     time.Time
	CompletedAt   time.Time
	TotalFiles    uint64
	ScannedFiles  uint64
	InfectedFiles uint64
	Quarantined   uint64
	Errors        uint64
	ProgressPct   float64
	CurrentPath   string
	SpeedFps      float64
	Message       string
}

type FileHashes struct {
	SHA256 string
	SHA1   string
	MD5    string
}

type PeInfo struct {
	Subsystem         string
	MachineType       string
	NumberOfSections  uint32
	SectionNames      []string
	ImportedDlls      []string
	ImportedFunctions []string
	ExportedFunctions []string
	CompileTimestamp  time.Time
	EntryPoint        string
	ImageBase         uint64
	SizeOfCode        uint32
	IsDriver          bool
	IsDll             bool
	HasAuthenticode   bool
	Packed            bool
	PackerName        string
}

type SignatureInfo struct {
	Signed           bool
	Verified         bool
	Signer           string
	Issuer           string
	Thumbprint       string
	Timestamp        time.Time
	CertificateChain []string
}

type ScanResult struct {
	ScanId           string
	FilePath         string
	FileName         string
	FileSize         uint64
	Hashes           *FileHashes
	Entropy          float64
	Score            float64
	HeuristicScore   float64
	EmberScore       float64
	NeedsSandbox     bool
	IsPe             bool
	PeInfo           *PeInfo
	Signature        *SignatureInfo
	MatchedYaraRules []string
	MatchedIocs      []string
	Verdict          string
	Quarantined      bool
	QuarantinePath   string
	ScannedAt        time.Time
	ScanDurationMs   uint64
}

type StopRequest struct {
	ScanId string
}

type StatusRequest struct {
	ScanId string
}

type ScanSummary struct {
	ScanId           string
	FinalStatus      string
	TotalFiles       uint64
	CleanFiles       uint64
	SuspiciousFiles  uint64
	MaliciousFiles   uint64
	QuarantinedFiles uint64
	Errors           uint64
	TotalDurationSecs float64
	TopThreats       []*ScanResult
}

type ScanAck struct {
	Received bool
}

type Empty struct{}

type ScannerHealthResponse struct {
	Healthy       bool
	Version       string
	UptimeSeconds uint64
	ActiveWorkers uint32
}

// --- gRPC Service Interface ---

type ScannerServiceServer interface {
	StartScan(context.Context, *ScanRequest) (*ScanStatusMessage, error)
	StopScan(context.Context, *StopRequest) (*ScanStatusMessage, error)
	GetScanStatus(context.Context, *StatusRequest) (*ScanStatusMessage, error)
	StreamScanResults(*StatusRequest, ScannerServiceStreamServer) error
	ReportScanSummary(context.Context, *ScanSummary) (*ScanAck, error)
	ScannerHealth(context.Context, *Empty) (*ScannerHealthResponse, error)
}

// UnimplementedScannerServiceServer should be embedded to have forward compatible implementations.
type UnimplementedScannerServiceServer struct{}

func (UnimplementedScannerServiceServer) StartScan(context.Context, *ScanRequest) (*ScanStatusMessage, error) {
	return nil, nil
}
func (UnimplementedScannerServiceServer) StopScan(context.Context, *StopRequest) (*ScanStatusMessage, error) {
	return nil, nil
}
func (UnimplementedScannerServiceServer) GetScanStatus(context.Context, *StatusRequest) (*ScanStatusMessage, error) {
	return nil, nil
}
func (UnimplementedScannerServiceServer) StreamScanResults(*StatusRequest, ScannerServiceStreamServer) error {
	return nil
}
func (UnimplementedScannerServiceServer) ReportScanSummary(context.Context, *ScanSummary) (*ScanAck, error) {
	return nil, nil
}
func (UnimplementedScannerServiceServer) ScannerHealth(context.Context, *Empty) (*ScannerHealthResponse, error) {
	return nil, nil
}

// ScannerServiceStreamServer is the server-side stream for StreamScanResults.
type ScannerServiceStreamServer interface {
	Send(*ScanResult) error
	Context() context.Context
}

type scannerServiceStreamImpl struct {
	send func(*ScanResult) error
	ctx  context.Context
}

func (s *scannerServiceStreamImpl) Send(m *ScanResult) error { return s.send(m) }
func (s *scannerServiceStreamImpl) Context() context.Context { return s.ctx }

// RegisterScannerServiceServer registers the scanner service with a gRPC server.
func RegisterScannerServiceServer(s grpc.ServiceRegistrar, svc ScannerServiceServer) {
	s.RegisterService(&ScannerService_ServiceDesc, svc)
}

// ScannerService_ServiceDesc is the gRPC service descriptor.
var ScannerService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "ScannerService",
	HandlerType: (*ScannerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StartScan",
			Handler:    _ScannerService_StartScan_Handler,
		},
		{
			MethodName: "StopScan",
			Handler:    _ScannerService_StopScan_Handler,
		},
		{
			MethodName: "GetScanStatus",
			Handler:    _ScannerService_GetScanStatus_Handler,
		},
		{
			MethodName: "ReportScanSummary",
			Handler:    _ScannerService_ReportScanSummary_Handler,
		},
		{
			MethodName: "ScannerHealth",
			Handler:    _ScannerService_ScannerHealth_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamScanResults",
			Handler:       _ScannerService_StreamScanResults_Handler,
			ServerStreams: true,
			ClientStreams: false,
		},
	},
	Metadata: "scanner.proto",
}

func _ScannerService_StartScan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ScanRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScannerServiceServer).StartScan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ScannerService/StartScan",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ScannerServiceServer).StartScan(ctx, req.(*ScanRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScannerService_StopScan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScannerServiceServer).StopScan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ScannerService/StopScan",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ScannerServiceServer).StopScan(ctx, req.(*StopRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScannerService_GetScanStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScannerServiceServer).GetScanStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ScannerService/GetScanStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ScannerServiceServer).GetScanStatus(ctx, req.(*StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScannerService_ReportScanSummary_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ScanSummary)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScannerServiceServer).ReportScanSummary(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ScannerService/ReportScanSummary",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ScannerServiceServer).ReportScanSummary(ctx, req.(*ScanSummary))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScannerService_ScannerHealth_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ScannerServiceServer).ScannerHealth(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ScannerService/ScannerHealth",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ScannerServiceServer).ScannerHealth(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _ScannerService_StreamScanResults_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(StatusRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ScannerServiceServer).StreamScanResults(m, &scannerServiceStreamImpl{
		send: func(r *ScanResult) error { return stream.SendMsg(r) },
		ctx:  stream.Context(),
	})
}
