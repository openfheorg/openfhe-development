# OpenFHE Project Main Governance Document v2.0

Policies and procedures governing the OpenFHE community

## Revision History

This is a living document and is expected to be updated in order to meet the changing needs as the OpenFHE organization
evolves over time.

* Version 0.1 Prerelease Placeholder 9/20/2019
* Version 0.2 Draft for Steering Team Approval 10/28/2019
* Version 1.0 Adopted by Steering Team 1/28/2020
* Version 2.0 Adopted by Steering Team 3/21/21
  * addition of Crypto Team and Advisory Board

**Note**: visit [PALISADE Governance](https://gitlab.com/palisade/palisade-development/-/blob/master/Governance.md) to view previous iterations of this document

# NumFOCUS Affiliation

OpenFHE is a Sponsored Project of NumFOCUS, a 501(c)(3) nonprofit charity in the United States. NumFOCUS provides
OpenFHE with fiscal, and administrative support to help ensure the health and sustainability of the project. Visit
([http://numfocus.org](http://numfocus.org)) for more information.

Donations to OpenFHE are managed by NumFOCUS. For donors in the United States, your gift is tax-deductible to the extent
provided by law. As with any donation, you should consult with your tax adviser about your particular tax situation.

OpenFHE has a formal legal and fiscial relationship with DUALITY Technologies.

# Teams & Roles

Here are defined the primary teams participating in OpenFHE activities. Note, individuals are able to participate in
multiple teams. The Steering team shall approve all changes in membership to all OpenFHE teams, and maintain a Google
Doc listing team member's names, contact info, and date of first inclusion into the team.

* **Steering:** The Steering team is the governing body over the entire OpenFHE organization. Members of the Steering
  team have full rights over all OpenFHE repositories. Members of the Steering team are the face of the project, and are
  responsible for officially interfacing with external communities, organizations, non-profits, and companies. The
  Steering team may create new teams, as appropriate. Each member of the Steering team is entitled to one vote on all
  elected matters.

* **Crypto:** The Crypto team is a group of members of the Homomorphic Encryption Community who have been invited to
  participate by the Steering Committee. The team should meet as needed but at least once every three months. If there
  is a situation requiring an immediate response, such as a newly published attack, the Team may call an “extraordinary”
  meeting. The Crypto Team recommends actions and responses. All recommendations must be agreed to unanimously by
  members of the Crypto Team. Recommendations are then passed on to the Steering Team for an immediate vote for
  adoption. Areas of responsibility of the Crypto Team are outlined as follows:

  * Decide whether a particular scheme/capability should be added or removed from an upcoming OpenFHE release.

  * Identify/recommend various hardening techniques, such as PRNG, Gaussian sampling, constant-time samplers, etc.

  * Discuss/recommend the choice and inclusion of new lattice parameter settings, e.g., non-power-of-two cyclotomics.

  * Develop/recommend any patches/fixes related to newly discovered vulnerabilities or attacks, and draft public
    announcements regarding those attacks and OpenFHE'S corresponding response. Note, all resulting draft
    announcements must then be approved by the Steering Team, which is then responsible for publishing the
    announcement accordingly.


* **Advisory Board:** The Advisory Board is a group of technologists and thought leaders expert in the HE field or
  associated application areas who have been invited to participate by the Steering Committee. The Board should meet
  with the Steering Team in an advisory session no more frequently than once every six months, with a minimum frequency
  of once every year. The role of the advisory board is to provide input and guidance to the Steering Team regarding
  emerging technologies, applications, and other agenda topics to be determined by the Steering Team for each meeting.

* **Pre-release:** The Pre-release team administers the current pre-release branch in the openfhe-development repository
  and is responsible for the review and publication of new pre-releases, as well as updates, patches and bug fixes to
  these pre-releases as they are evaluated for submission to stable-release status. The Pre-release team determines
  which features in the main branch of openfhe-development are sufficiently mature to be chosen for pre-release. They
  also are responsible for quality control checking of associated documentation related to the pre-release. The team
  will follow the guidelines (below) for release numbering. Pre-release of Major releases (i.e. incrementing the initial
  release number) have significant impact and must be approved by the Steering team.

* **Stable-release:** The Stable-release team administers the OpenFHE stable release repository and is responsible for
  the review and publication of new stable releases, as well as the physical migration of the candidate pre-release and
  associated documentation to the stable release repostiory. It also is responsible for updating or patching the stable
  releases as applicable. The stable-release team will determine at what point in time a current pre-release is stable
  enough to be moved to the release repository according the the following suggested guidelines:

  * The candidate pre-release has been tested independently by members of the community and no severe issues have been
    reported. Also no severe issues have been reported by the OpenFHE Maintainers team.

  * Sufficient time has passed for such independent review to occur. The duration of this review period is up to the
    judgement of the stable-release team and should be based on the number of new features and/or scope of patches
    applied since the last pre-release update.

  * These guidlines are meant to be flexible to the needs of the community while maintaining overall software quality
    of the OpenFHE release. As such, interested users may request an expedited (i.e. shorter) testing period provided
    they can assist with the required testing and evaluation. Such requests must be reviewd and approved by both the
    Stable-release team and the Steering team.

* **Maintainers:** A Maintainer is an individual responsible for the management of the OpenFHE-development repository.
  Maintainers have the ability to commit/push source code and can handle merge/pull requests into the main branch of the
  repository with the following caveats:

  * Merge/Pull requests from internal OpenFHE Maintatiners require the review of one other member of the Maintainer
    team (i.e. a Maintainer cannot Merge their own branches).

  * Merge/Pull requests from External contributors require an extra level of review and approval from the entire
    Maintainer team.

* **External contributors:** This group encompasses all others who are not on the Steering team, Pre-release, Release or
  Maintainers teams. This includes first-time contributors, collaborators, and funders. They have no special rights
  within the OpenFHE organization itself. External contributors are strongly encouraged to discuss potential
  contributions with the Maintainers and/or Steering committee members before proceeding with any major development, in
  order to ensure their intended work will align with work already in progress, or in planning.

* **Emeritus status:** Steering team members that are inactive
  (commits, GitHub comments/issues/reviews, dev meetings and voting on polls) in the past six months will be asked if
  they want to become Emeritus. Any member of a OpenFHE team can also request to become Emeritus if they wish to do so (
  e.g. taking a sabbatical or long vacation). Emeritus Steering team members can still vote and resume active status
  anytime, the only difference is that Emeritus-Steering team members will not count against the total Steering team
  members when computing the necessary votes a poll needs to pass. The membership Google Doc list should be updated when
  change in the status of a member occurs.

## Sub-Teams

The Steering team may elect to create new sub-teams for managing the daily business of the organization. While sub-teams
may have non-Steering members, every sub-team must have at least one Steering team member at all times. If a sub-team
fails to have a Steering team member for more than 2 weeks, that team is considered to be dissolved. A new sub-team
would need to be established by the Steering team in order to reinstate the activity.

Sub-teams have a charter that is either *dynamic* or *static*.

* A *dynamic* charter means that the sub-team is self-organizing, with respect to its own internal policies, procedures,
  and membership. A sub-team may choose to modify its membership independent of the steering committee. For example, a
  Google Summer of Code team could be a good candidate for a dynamic charter. Alternatively, language-based maintenance
  teams also have a dynamic charter.

* A *static* charter means that all membership decisions and non-trivial policies changes must be approved by the
  steering committee. For example, a finance team may require a static charter.

All sub-teams must adhere to the governance, policies, and procedures of OpenFHE at all times.

# Voting

This section presents descriptions and criteria for voting items in the OpenFHE community. The Steering team is the only
team with voting rights. Other teams may pass recommendations up to the Steering team for a vote. The members of the
Steering team may also call a vote on any topic. The restrictions on calling a vote are as follows:

* There must only be one vote active on a particular item at any time.
* The act of calling for a vote cannot itself violate the code of conduct. For example, Sam repeatedly called for votes
  immediately after a previous vote failed to achieve Sam's result. Sam is attempting to bully other members of core
  into agreeing, and is thus violating the code of conduct.
* Voting yes moves the proposal forward; voting no is the only way to express opposition to the proposal; not voting is
  discouraged, but non-votes do not count as "no".
* There should always be an option to abstain from voting.

Voting items are labeled as either **standard** or **sensitive**. Standard items are ones where public record and
discourse is preferable. Sensitive voting items are ones where the results of the vote should remain private to the
voters after the vote has occurred. Sensitive votes should take place on `the Helios voting system
<https://vote.heliosvoting.org/>`_ in order retain anonymity.

The default voting period is 1 week (7 days). This may be modified at the time when a vote is called, but may never be
less than 24 hrs.

Votes can happen on the following topics, with passing contingent on a 2/3 majority. All Steering team members should
vote, but abstentions are permitted. Sample voting topics are as follows (but are not limited to this list):

* Modifications of these governance procedures (including permanently modifying these lists of sample voting topics).
* Adding/removing Steering team members Spending project funds
* Adding/removing people with commit rights to GitLab repositories
* Adding/removing moderators of OpenFHE online groups and forums
* Adding/removing people to private communication channels
* Adding/removing people with rights to post as OpenFHE on social
* media Establishing sub-committees and roles

Votes can happen on the following topics with passing contingent on a majority. At least 2/3 of the Steering team
members should vote, but abstentions are permitted. Sample voting topics are as follows (but are not limited to this
list):

* Approving an expedited release testing schedule
* Approving a Major Pre-release

The Steering team will maintain a Google Doc that records all votes
(but not discussion). Access to the Google Doc will be limited to members of the Steering team.

# Release numbering

Releases shall be numbered sequentially using the following triple numbering:

Major.minor.patch

Major release number must be incremented when the OpenFHE user API changes, requiring user code rewrite.

Minor release numbers must be incremented when a new capability is added, or old capability is deprecated, but existing
user code would still operate without a rewrite.

Patch release numbers must be incremented when patches/bug fixes are required.

When a Major pre-release is approved, the Major number is incremented from the last release and minor and patch are set
to zero.

When a Minor pre-release is approved the Minor number is incremented from the lasts relese and the patch is set to zero.

When a pre-release is patched, the pre-release Major and Minor numbers are maintained, and the patch is incremented.

When a pre-release is approved for stable-release, the pre-release Major and Minor numbers are maintained, and the patch
is incremented.

When a stable-release is patched, the pre-release Major and Minor numbers are maintained, and the patch is incremented.
The patches applied to the stable-release are to be applied to the main branch of the development release as
appropriate.

At no time will there be multiple pre-release versions supported. Only the latest pre-release will be considered active.

Once a pre-release is accepted for stable release, that pre-release is considered inactive.
