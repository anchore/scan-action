import os
import pytest

@pytest.fixture(scope="module")
def image_output():
    dirname = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(dirname, 'output/image.output')
    with open(output_file) as _f:
        return _f.read()


class TestSmoke:

    # basic validation
    def test_zero_exit_status(self, image_output):
        lines = image_output.split()
        fail_context = '\n'.join(image_output.split('\n')[-20:])
        assert lines[-1] == '0', fail_context

    def test_found_vulnerabilities(self, image_output):
        assert "Failed minimum severity level. Found vulnerabilities with level medium or higher" in image_output
