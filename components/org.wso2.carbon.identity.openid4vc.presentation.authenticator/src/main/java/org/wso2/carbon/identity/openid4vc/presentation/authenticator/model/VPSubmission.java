package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

/**
 * Model class representing a Verifiable Presentation Submission.
 * This stores the VP token submitted by the wallet for transient handoff to the poller.
 */
public class VPSubmission {


    /**
     * The ID of the request this submission belongs to.
     */
    private String state;

    /**
     * The VP token string submitted by the wallet.
     */
    private String vpToken;

    /**
     * The presentation submission JSON string.
     */
    private String presentationSubmission;

    /**
     * Default constructor for VPSubmission.
     */
    public VPSubmission() {

    }

    /**
     * Get the request ID associated with this submission.
     *
     * @return The request ID string.
     */
    public String getRequestId() {

        return state;
    }

    /**
     * Set the request ID associated with this submission.
     *
     * @param requestId The request ID string.
     */
    public void setRequestId(String requestId) {

        this.state = requestId;
    }

    /**
     * Get the VP token string.
     *
     * @return The VP token string.
     */
    public String getVpToken() {

        return vpToken;
    }

    /**
     * Set the VP token string.
     *
     * @param vpToken The VP token string.
     */
    public void setVpToken(String vpToken) {

        this.vpToken = vpToken;
    }

    /**
     * Get the presentation submission JSON.
     *
     * @return The presentation submission JSON string.
     */
    public String getPresentationSubmission() {

        return presentationSubmission;
    }

    /**
     * Set the presentation submission JSON.
     *
     * @param presentationSubmission The presentation submission JSON string.
     */
    public void setPresentationSubmission(String presentationSubmission) {

        this.presentationSubmission = presentationSubmission;
    }

    @Override
    public String toString() {

        return "VPSubmission{" +
                "state='" + state + '\'' +
                ", hasVpToken=" + (vpToken != null && !vpToken.isEmpty()) +
                ", hasPresentationSubmission=" + (presentationSubmission != null && !presentationSubmission.isEmpty()) +
                '}';
    }
}
