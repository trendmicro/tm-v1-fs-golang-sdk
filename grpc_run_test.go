package client

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/trendmicro/tm-v1-fs-golang-sdk/protos"
)

/***************************************************************************

One of the most critical functional areas for us to test with the AMaaS
client is that given a command from the server, the client will actually
carry out the task requested by the server, namely, retrieving the right
data chunk from the file when requested by the server.

***************************************************************************/

// This class will generate a temporary file with consecutive sequences of
// extended ASCII codes from 0 to 255 in ascending order, where each code
// occupies one (1) byte. For example, a file that is exactly 256 bytes long
// would be [0x00, 0x01, 0x02, ... , 0xFD, 0xFE, 0xFF] while a file that is
// exactly 512 bytes long would be [0x00, 0x01, 0x02, ... , 0xFD, 0xFE, 0xFF,
// 0x00, 0x01, 0x02, ... , 0xFD, 0xFE, 0xFF].

const (
	EnvVarTestDatDir      = "AMAAS_UNIT_TEST_GOLANG_DIR"
	DefaultTestDatDirPath = "."
	MaxFileSize           = 1 << 20
	MaxChunkReadSize      = 1 << 12
	NumReadIterations     = 1 << 14
)

type TestDat struct {
	filesize int
	filename string
	sha1     string
	sha256   string
}

func createTestDat(fnameTemplate string) *TestDat {

	tempDir := os.Getenv(EnvVarTestDatDir)
	if tempDir == "" {
		tempDir = DefaultTestDatDirPath
	}

	file, err := os.CreateTemp(tempDir, fnameTemplate)
	if err != nil {
		return nil
	}

	d := &TestDat{
		filesize: MaxFileSize,
		filename: file.Name(),
	}

	fd, err := os.Create(d.filename)
	if err != nil {
		return nil
	}
	defer fd.Close()

	b := make([]byte, d.filesize)
	for i := 0; i < d.filesize; i++ {
		b[i] = byte(i % 256)
	}

	sha1 := sha1.New()
	sha1.Write(b)

	sha256 := sha256.New()
	sha256.Write(b)

	d.sha1 = fmt.Sprintf("sha1:%s", hex.EncodeToString(sha1.Sum(nil)))
	d.sha256 = fmt.Sprintf("sha256:%s", hex.EncodeToString(sha256.Sum(nil)))

	if n, err := fd.Write(b); err != nil || n != d.filesize {
		return nil
	}

	return d
}

func (d *TestDat) ExpectedValueAt(pos int) byte {
	return byte(pos % 256)
}

func (d *TestDat) Filename() string {
	return d.filename
}

func (d *TestDat) Filesize() int {
	return d.filesize
}

func (d *TestDat) Sha1() string {
	return d.sha1
}

func (d *TestDat) Sha256() string {
	return d.sha256
}

// Test readFileBytes() function which is critical to client retrieval
// of file content.

func TestReadFileBytes(t *testing.T) {

	dat := createTestDat("test.*.dat")
	defer os.Remove(dat.Filename())

	fileReader, err := InitFileReader(dat.Filename())
	assert.Nil(t, err)
	defer fileReader.Close()

	result, err := fileReader.DataSize()
	assert.Nil(t, err)

	fileSize := int(result)

	for i := 0; i < NumReadIterations; i++ {
		offset := rand.Intn(fileSize)
		length := rand.Intn(MaxChunkReadSize) + 1
		end := offset + length
		if end > fileSize {
			length -= (end - fileSize)
		}

		buf, err := fileReader.ReadBytes(int64(offset), int32(length))
		assert.Nil(t, err)
		assert.NotNil(t, len(buf) == length)

		for j := 0; j < length; j++ {
			expected := dat.ExpectedValueAt(offset + j)
			result := buf[j]
			assert.Equal(t, expected, result)
		}
	}
}

// Mock client stream for testing
// Essentially we're using channel here to simulate flow of commands/replies
// from the server to the client (response messages per RPC convention), and
// from client to the server (request messages per RPC convention).
//
// In the case of AMaaS client-server design, it's actually the server
// issuing commands to the client using S2C messages, and the client reading
// data chunks off the file and sending them back to the server using C2S
// messages.

type ClientStreamMock struct {
	grpc.ClientStream
	recvToClient   chan *pb.S2C
	sentFromClient chan *pb.C2S
}

func createClientStreamMock() *ClientStreamMock {
	return &ClientStreamMock{
		recvToClient:   make(chan *pb.S2C, NumReadIterations),
		sentFromClient: make(chan *pb.C2S, NumReadIterations),
	}
}

func (mock *ClientStreamMock) Send(req *pb.C2S) error {
	mock.sentFromClient <- req
	return nil
}

func (mock *ClientStreamMock) Recv() (*pb.S2C, error) {

	resp, more := <-mock.recvToClient
	if !more {
		return nil,
			errors.New("Simulated stream is now empty of server2client responses")
	}
	return resp, nil
}

func (mock *ClientStreamMock) SendFromServer(resp *pb.S2C) error {
	mock.recvToClient <- resp
	return nil
}

func (mock *ClientStreamMock) RecvToServer() (*pb.C2S, error) {
	req, more := <-mock.sentFromClient
	if !more {
		return nil,
			errors.New("Simulated stream is now empty of client2server requests")
	}
	return req, nil
}

// Test gRPC client runUploadLoop() function to make sure it processes the
// RETR commands from the server correctly.
//
// Also some testing of abnormal conditions, but more unit tests will be
// added to make sure the loop handles all sorts of different abnormal
// conditions later on.
//

// Global channel for storing errors generated by runUploadLoop(). Depending
// on the testcase, this channel might be completely empty or containing
// some error.

var errChan chan error = make(chan error, NumReadIterations)

func createMockClientRun(t *testing.T, reader AmaasClientReader, bulk bool) *ClientStreamMock {

	stream := createClientStreamMock()

	go func() {
		_, _, err := runUploadLoop(stream, reader, bulk)
		if err != nil {
			errChan <- err
		}
		close(stream.sentFromClient)
		close(stream.recvToClient)
	}()

	return stream
}

// Test normal read conditions where client receives all valid
// S2C messages directing client to read from valid positions within
// the length of the file.
//
// This version exercises the loop using a buffer reader (as opposed to
// file reader) by reading in all the data from a test dat file into a
// byte slice, and then feeding the buffer to a buffer reader which is
// used during testing.

func TestRunUploadLoopNormalForBufferReader(t *testing.T) {

	dat := createTestDat("test.*.dat")
	assert.NotNil(t, dat)
	defer os.Remove(dat.Filename())

	// Read the content of the whole file into a byte slice.
	buffer, err := os.ReadFile(dat.Filename())
	assert.Nil(t, err)

	// Pass the buffer to a buffer reader.
	reader, err := InitBufferReader(buffer, dat.Filename())
	assert.Nil(t, err)
	defer reader.Close()

	checkRunUploadLoop(t, dat, reader, false)
}

func TestRunUploadLoopNormalForBufferReaderBulk(t *testing.T) {

	dat := createTestDat("test.*.dat")
	assert.NotNil(t, dat)
	defer os.Remove(dat.Filename())

	// Read the content of the whole file into a byte slice.
	buffer, err := os.ReadFile(dat.Filename())
	assert.Nil(t, err)

	// Pass the buffer to a buffer reader.
	reader, err := InitBufferReader(buffer, dat.Filename())
	assert.Nil(t, err)
	defer reader.Close()

	checkRunUploadLoop(t, dat, reader, true)
}

// Test normal read conditions where client receives all valid
// S2C messages directing client to read from valid positions within
// the length of the file.
//
// Unlike the other, earlier test, this one uses a file reader instead
// of a buffer reader. The dat filename is directly passed to the file
// reader which is used during testing.

func TestRunUploadLoopNormalForFileReader(t *testing.T) {

	dat := createTestDat("test.*.dat")
	assert.NotNil(t, dat)
	defer os.Remove(dat.Filename())

	reader, err := InitFileReader(dat.Filename())
	assert.Nil(t, err)
	defer reader.Close()

	checkRunUploadLoop(t, dat, reader, false)
}

func TestRunUploadLoopNormalForFileReaderBulk(t *testing.T) {

	dat := createTestDat("test.*.dat")
	assert.NotNil(t, dat)
	defer os.Remove(dat.Filename())

	reader, err := InitFileReader(dat.Filename())
	assert.Nil(t, err)
	defer reader.Close()

	checkRunUploadLoop(t, dat, reader, true)
}

func checkRunUploadLoop(t *testing.T, dat *TestDat, reader AmaasClientReader, bulk bool) {
	stream := createMockClientRun(t, reader, bulk)
	assert.NotNil(t, stream)

	reads := make([](*pb.S2C), NumReadIterations)

	for i := 0; i < NumReadIterations; i++ {
		var s2c *pb.S2C
		if bulk {
			s2c = generateRetrS2CBulk(dat.Filesize())
			assert.NotNil(t, s2c)
		} else {
			s2c = generateRetrS2C(dat.Filesize())
			assert.NotNil(t, s2c)
		}

		err := stream.SendFromServer(s2c)
		assert.Nil(t, err)
		reads[i] = s2c
	}

	// No reason for runUploadLoop() to send any error into the
	// error channel. Something is wrong if non-empty.

	assert.Equal(t, 0, len(errChan))

	for i := 0; i < NumReadIterations; i++ {
		resp, err := stream.RecvToServer()
		assert.Nil(t, err)
		assert.NotNil(t, resp)

		if bulk {
			verifyC2SRespBulk(t, dat, reads[i], resp)
		} else {
			verifyC2SResp(t, dat, reads[i], resp)
		}
	}
}

func generateRetrS2C(fileSize int) *pb.S2C {
	offset := rand.Intn(fileSize)
	len := rand.Intn(MaxChunkReadSize) + 1
	end := offset + len
	if end > fileSize {
		len -= (end - fileSize)
	}

	return &pb.S2C{
		Stage:  pb.Stage_STAGE_RUN,
		Cmd:    pb.Command_CMD_RETR,
		Offset: int32(offset),
		Length: int32(len),
	}
}

func generateRetrS2CBulk(fileSize int) *pb.S2C {
	offset := rand.Intn(fileSize)
	length := rand.Intn(MaxChunkReadSize) + 1
	end := offset + length
	if end > fileSize {
		length -= (end - fileSize)
	}

	bulkLength := []int32{int32(length)}
	bulkOffset := []int32{int32(offset)}

	return &pb.S2C{
		Stage:      pb.Stage_STAGE_RUN,
		Cmd:        pb.Command_CMD_RETR,
		BulkLength: bulkLength,
		BulkOffset: bulkOffset,
	}
}

func verifyC2SResp(t *testing.T, dat *TestDat, req *pb.S2C, resp *pb.C2S) {
	assert.Equal(t, pb.Stage_STAGE_RUN, resp.Stage)
	assert.Equal(t, req.Offset, resp.Offset)

	origLen := int(req.Length)
	assert.Equal(t, origLen, len(resp.Chunk))

	for i := 0; i < origLen; i++ {
		assert.Equal(t, dat.ExpectedValueAt(int(req.Offset)+i), resp.Chunk[i])
	}
}

func verifyC2SRespBulk(t *testing.T, dat *TestDat, req *pb.S2C, resp *pb.C2S) {
	assert.Equal(t, pb.Stage_STAGE_RUN, resp.Stage)
	assert.Equal(t, req.BulkOffset[0], resp.Offset)

	origLen := int(req.BulkLength[0])
	assert.Equal(t, origLen, len(resp.Chunk))

	for i := 0; i < origLen; i++ {
		assert.Equal(t, dat.ExpectedValueAt(int(req.BulkOffset[0])+i), resp.Chunk[i])
	}
}

// Test condition where the S2C command to the client is simply
// some invalid garbage.

func TestRunUploadLoopBadS2CMsg(t *testing.T) {

	reader, err := InitBufferReader(make([]byte, 10), "whatever")
	assert.Nil(t, err)

	stream := createMockClientRun(t, reader, false)
	assert.NotNil(t, stream)

	s2c := &pb.S2C{
		Stage:  pb.Stage(100),
		Cmd:    pb.Command(200),
		Offset: 0,
		Length: 0,
	}

	err = stream.SendFromServer(s2c)
	assert.Nil(t, err)

	// runUploadLoop() should have sent 1 error into the channel due
	// to not able to interpret the received command message.
	err = <-errChan
	assert.NotNil(t, err)

	st, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, st.Code())

	// There should be no C2S message sent by the client into the
	// simulated message channel, so trying to read from the message
	// channel should result in an error.

	_, err = stream.RecvToServer()
	assert.NotNil(t, err)
}

func TestScanRunWithInvalidTags(t *testing.T) {
	tests := []struct {
		name        string
		tags        []string
		expectedErr string
	}{
		{
			name:        "Empty tags",
			tags:        []string{},
			expectedErr: "tags cannot be empty",
		},
		{
			name:        "Too many tags",
			tags:        []string{"tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7", "tag8", "tag9"},
			expectedErr: "too many tags, maximum is 8",
		},
		{
			name:        "Empty tag",
			tags:        []string{"", "tag1"},
			expectedErr: "each tag cannot be empty",
		},
		{
			name:        "Tag length exceeds 63",
			tags:        []string{"1234567890123456789012345678901234567890123456789012345678901234"},
			expectedErr: "tag length cannot exceed 63",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// arrange
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(180))

			// act
			_, err := scanRun(ctx, cancel, nil, nil, tt.tags, false, true, false, false, false, true)

			// assert
			assert.Equal(t, tt.expectedErr, err.Error())
		})
	}
}
