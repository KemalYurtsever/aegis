import { Component } from "react";

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error("AEGIS interface error", error, errorInfo);
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <main className="fatal-error" role="alert">
        <section className="fatal-error__card">
          <span className="fatal-error__eyebrow">AEGIS RECOVERY</span>
          <h1>The interface could not finish loading</h1>
          <p>
            Your monitoring data is unchanged. Reload the interface, then review
            the frontend log if this screen returns.
          </p>
          <button className="button button--primary" type="button" onClick={() => window.location.reload()}>
            Reload AEGIS
          </button>
        </section>
      </main>
    );
  }
}
