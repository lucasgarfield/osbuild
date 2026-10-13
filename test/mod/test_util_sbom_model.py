import pytest

from osbuild.util.sbom.model import rpm_repository_id, RPMPackage


def test_rpmpackage_uuid():
    pkg_a = RPMPackage("PackageA", "1.0.0", "1.fc40", "x86_64")
    pkg_a_duplicate = RPMPackage("PackageA", "1.0.0", "1.fc40", "x86_64")

    pkg_a_v2 = RPMPackage("PackageA", "2.0.0", "1.fc40", "x86_64")
    pkg_a_fc41 = RPMPackage("PackageA", "1.0.0", "1.fc41", "x86_64")
    pkg_a_aarch64 = RPMPackage("PackageA", "1.0.0", "1.fc40", "aarch64")

    pkg_b = RPMPackage("PackageB", "1.0.0", "1.fc40", "x86_64")

    assert pkg_a.uuid() == pkg_a_duplicate.uuid()
    for pkg in [pkg_a_v2, pkg_a_fc41, pkg_a_aarch64, pkg_b]:
        assert pkg_a.uuid() != pkg.uuid()


@pytest.mark.parametrize("package,purl", (
    (
        RPMPackage("PackageA", "1.0.0", "1.fc40", "x86_64"),
        "pkg:rpm/PackageA@1.0.0-1.fc40?arch=x86_64"
    ),
    (
        RPMPackage("PackageA", "1.0.0", "1.fc40", "x86_64", epoch=123),
        "pkg:rpm/PackageA@1.0.0-1.fc40?arch=x86_64&epoch=123"
    ),
    (
        RPMPackage("PackageA", "1.0.0", "1.fc40", "x86_64", vendor="Fedora Project"),
        "pkg:rpm/fedora/PackageA@1.0.0-1.fc40?arch=x86_64"
    ),
    (
        RPMPackage("PackageA", "1.0.0", "1.el9", "x86_64", vendor="CentOS"),
        "pkg:rpm/centos/PackageA@1.0.0-1.el9?arch=x86_64"
    ),
    (
        RPMPackage("PackageA", "1.0.0", "1.el9", "x86_64", vendor="Red Hat, Inc."),
        "pkg:rpm/redhat/PackageA@1.0.0-1.el9?arch=x86_64"
    ),
    (
        RPMPackage("PackageA", "1.0.0", "1.fc40", "x86_64", vendor="Fedora Project",
                   repository_url="https://example.org/repo/", repository_id="fedora"),
        "pkg:rpm/fedora/PackageA@1.0.0-1.fc40?arch=x86_64&repository_id=fedora"
    ),

))
def test_rpmpackage_purl(package, purl):
    assert package.purl() == purl


@pytest.mark.parametrize("repo_id,repo_name,expected", (
    ("rhel-9-for-x86_64-baseos-rpms", "BaseOS", "rhel-9-for-x86_64-baseos-rpms"),
    ("5d7f" * 16, "BaseOS", "baseos"),
    ("5d7f" * 16, "Fedora 44 - x86_64", "fedora-44-x86_64"),
    ("@System", "", ""),
))
def test_rpm_repository_id(repo_id, repo_name, expected):
    assert rpm_repository_id(repo_id, repo_name) == expected


def test_rpmpackage_source_rpm():
    pkg = RPMPackage("bash", "5.2.37", "1.fc44", "x86_64", epoch=1, vendor="Fedora Project",
                     source_rpm="bash-5.2.37-1.fc44.src.rpm")
    assert pkg.source_rpm_nvr() == ("bash", "5.2.37", "1.fc44")
    assert pkg.source_rpm_purl() == "pkg:rpm/fedora/bash@5.2.37-1.fc44?arch=src&epoch=1"
    assert RPMPackage("x", "1", "1", "noarch", source_rpm="garbage").source_rpm_purl() is None
