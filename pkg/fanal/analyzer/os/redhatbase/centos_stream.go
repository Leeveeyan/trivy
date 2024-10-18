package redhatbase

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

const centosStreamAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&centOSStreamAnalyzer{})
}

type centOSStreamAnalyzer struct{}

func (a centOSStreamAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("centos stream: invalid centos-release")
		}

		switch strings.ToLower(result[1]) {
		case "centos stream":
			return &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.RedHat,
					Name:   result[2],
				},
			}, nil
		}
	}

	return nil, xerrors.Errorf("centos: %w", fos.AnalyzeOSError)
}

func (a centOSStreamAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a centOSStreamAnalyzer) requiredFiles() []string {
	return []string{"etc/centos-release"}
}

func (a centOSStreamAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCentOSStream
}

func (a centOSStreamAnalyzer) Version() int {
	return centosStreamAnalyzerVersion
}
