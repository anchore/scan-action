import os
import pytest

@pytest.fixture(scope="module")
def invalid_output():
    dirname = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(dirname, 'output/invalid-input.output')
    with open(output_file) as _f:
        return _f.read()


class TestInvalidInput:

    # unfortunately, non-zero is not enough, we want to make sure that there
    # is something preventing invalid input altogether
    def test_nonzero_exit_status(self, invalid_output):
        lines = invalid_output.split()
        assert lines[-1] == '1'

    def test_vulns_arent_reported(self, invalid_output):
        # nothing should really get reported from grype because the input is not good
        lines = invalid_output.split('\n')
        for line in lines:
            assert "discovered vulnerabilities at or above the severity threshold" not in line

    def test_error_is_reported(self, invalid_output):
        assert "The following options are mutually exclusive: image, path, sbom" in invalid_output

    def test_grype_never_runs(self, invalid_output):
        lines = invalid_output.split('\n')
        for line in lines:
            assert "Running cmd: grype -vv -o json" not in line


@pytest.fixture(scope="module")
def sources_output():
    dirname = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(dirname, 'output/no-sources.output')
    with open(output_file) as _f:
        return _f.read()


class TestNoSources:

    def test_nonzero_exit_status(self, sources_output):
        lines = sources_output.split()
        assert lines[-1] == '1'

    def test_vulns_arent_reported(self, sources_output):
        # nothing should really get reported from grype because there are no sources to use
        lines = sources_output.split('\n')
        for line in lines:
            assert "discovered vulnerabilities at or above the severity threshold" not in line

    def test_error_is_reported(self, sources_output):
        assert "At least one source for scanning needs to be provided. Available options are: image, path and sbom" in sources_output

    def test_grype_never_runs(self, sources_output):
        lines = sources_output.split('\n')
        for line in lines:
            assert "Running cmd: grype -vv -o json" not in line
