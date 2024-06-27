from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from mergepo import MERGEPO_PATH, MergePO

TEST_DATA_PATH = MERGEPO_PATH / "test_data"


@dataclass(frozen=True)
class Paths:
    """Encapsulates paths of test data files for a specific test function"""

    base_path: Path
    answer_path: Path
    exported_path: Optional[Path]

    @classmethod
    def from_test_name(cls, test_name: str):
        base_path = TEST_DATA_PATH / test_name / "base.po"
        answer_path = TEST_DATA_PATH / test_name / "answer.po"
        exported_path = TEST_DATA_PATH / test_name / "exported.po"
        return cls(
            base_path=base_path, answer_path=answer_path, exported_path=exported_path
        )


@pytest.fixture
def output_path():
    return TEST_DATA_PATH / "temp.po"


def test_duplication(output_path: Path):
    paths = Paths.from_test_name("duplication")
    MergePO(base_path=paths.base_path, output_path=output_path).start()
    assert output_path.read_text() == paths.answer_path.read_text()


def test_exported(output_path: Path):
    paths = Paths.from_test_name("exported")
    MergePO(
        base_path=paths.base_path,
        exported_path=paths.exported_path,
        output_path=output_path,
    ).start()
    assert output_path.read_text() == paths.answer_path.read_text()


def test_no_occurrences_1(output_path: Path):
    paths = Paths.from_test_name("no_occurrences_1")
    MergePO(base_path=paths.base_path, output_path=output_path).start()
    assert output_path.read_text() == paths.answer_path.read_text()


def test_no_occurrences_2(output_path: Path):
    paths = Paths.from_test_name("no_occurrences_2")
    MergePO(
        base_path=paths.base_path,
        exported_path=paths.exported_path,
        output_path=output_path,
    ).start()
    assert output_path.read_text() == paths.answer_path.read_text()


def test_sorting(output_path: Path):
    paths = Paths.from_test_name("sorting")
    MergePO(
        base_path=paths.base_path,
        output_path=output_path,
        sort_entries=True,
        sort_references=True,
    ).start()
    assert output_path.read_text() == paths.answer_path.read_text()


def test_matching(output_path: Path):
    paths = Paths.from_test_name("matching")
    MergePO(
        base_path=paths.base_path,
        exported_path=paths.exported_path,
        output_path=output_path,
        regex="message[3-9]",
    ).start()
    assert output_path.read_text() == paths.answer_path.read_text()
