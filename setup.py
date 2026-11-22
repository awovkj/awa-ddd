"""Build hooks that keep in-package regression tests out of distributions."""
from __future__ import annotations

from pathlib import PurePosixPath

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist


def _private_test(parts):
    path = PurePosixPath(*parts)
    return len(path.parts) == 2 and path.parts[0] == "awa_ddd" \
        and path.name.startswith("tests_") and path.suffix == ".py"


class DistributionBuildPy(build_py):
    """Remove package-local regression modules from the wheel payload."""

    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        return [module for module in modules if not _private_test((module[0].replace(".", "/"), module[1] + ".py"))]


class DistributionSdist(sdist):
    """Apply the same public-source boundary to the source distribution."""

    def make_release_tree(self, base_dir, files):
        public = []
        for filename in files:
            paths = PurePosixPath(filename.replace("\\", "/")).parts
            if _private_test(paths) or paths and paths[0] == "tests":
                continue
            public.append(filename)
        super().make_release_tree(base_dir, public)


setup(cmdclass={"build_py": DistributionBuildPy, "sdist": DistributionSdist})
