using System;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using TraceCommons.App.ViewModels;
using TraceCommons.Interop;

namespace TraceCommons.App.Controls;

/// <summary>
/// The Settings screen's markup and wiring.
///
/// Thin by design, like <see cref="HistoryView"/> and <see cref="PreviewSheet"/>:
/// device behavior lives in <see cref="ContributorSettingsViewModel"/> and
/// profile behavior in <see cref="PublicProfileViewModel"/>. Contract shapes
/// and serializers live one layer further down in TraceCommons.Interop so
/// they can be tested off Windows. This file wires controls and one dialog.
///
/// Nothing here is logged. A handle and a bio are public by construction, but
/// they are contributor identity and never reach a log line.
/// </summary>
public sealed partial class SettingsView : UserControl
{
    private bool _tokenContributionDialogOpen;
    private bool _inferenceEvidenceDialogOpen;

    public SettingsView(DaemonHost host)
    {
        InitializeComponent();

        ViewModel = new PublicProfileViewModel(host);
        Settings = new ContributorSettingsViewModel(host);
        Loaded += OnFirstLoaded;
    }

    public PublicProfileViewModel ViewModel { get; }

    public ContributorSettingsViewModel Settings { get; }

    /// <summary>
    /// Reads the profile once the view is on screen rather than in the
    /// constructor, matching <see cref="HistoryView"/>: an IPC call that runs
    /// before the pane has been laid out reads as the nav click having done
    /// nothing.
    /// </summary>
    private async void OnFirstLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnFirstLoaded;
        await Task.WhenAll(ViewModel.LoadAsync(), Settings.LoadAsync());
    }

    /// <summary>
    /// Asks the window for the model-calls destination, which owns the
    /// switch now.
    ///
    /// <para>
    /// Raised as an event rather than navigating from here: this control is
    /// one pane's content and knows nothing about the rail it sits in, and a
    /// reference back to the window would be the only one in the file.
    /// </para>
    /// </summary>
    public event EventHandler? OpenPrivateInferenceRequested;

    private void OnOpenPrivateInference(object sender, RoutedEventArgs e)
    {
        OpenPrivateInferenceRequested?.Invoke(this, EventArgs.Empty);
    }

    private async void OnDisableInferenceEvidence(object sender, RoutedEventArgs e)
    {
        await Settings.SetInferenceEvidenceAsync(false);
    }

    private async void OnInferenceEvidence(object sender, RoutedEventArgs e)
    {
        if (_inferenceEvidenceDialogOpen || !Settings.InferenceEvidenceControlsEnabled)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = Settings.InferenceEvidenceHeading,
            Content = new ScrollViewer
            {
                Content = new TextBlock
                {
                    Text = string.Join("\n\n", Settings.InferenceEvidenceDisclosure,
                        Settings.InferenceEvidenceCaptureNote, Settings.InferenceEvidenceScopeNote),
                    TextWrapping = TextWrapping.Wrap,
                },
            },
            PrimaryButtonText = Settings.InferenceEvidenceConfirm,
            CloseButtonText = Settings.InferenceEvidenceCancel,
            DefaultButton = ContentDialogButton.Close,
        };

        _inferenceEvidenceDialogOpen = true;
        try
        {
            if (await DialogGuard.ShowOnceAsync(dialog) == ContentDialogResult.Primary)
            {
                await Settings.SetInferenceEvidenceAsync(true, disclosureConfirmed: true);
            }
        }
        finally
        {
            _inferenceEvidenceDialogOpen = false;
        }
    }
    private async void OnLocalProbabilityCapture(object sender, RoutedEventArgs e) {
        if (Settings.ProbabilityStorage is not { } storage) return;
        if (storage.CaptureEnabled) { await Settings.SetLocalProbabilityCaptureAsync(false); return; }
        var dialog = new ContentDialog { XamlRoot = XamlRoot, Title = storage.CaptureLabel,
            Content = storage.CaptureConfirmation, PrimaryButtonText = storage.CaptureLabel,
            CloseButtonText = storage.CancelLabel, DefaultButton = ContentDialogButton.Close };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary) await Settings.SetLocalProbabilityCaptureAsync(true);
    }
    private async void OnCleanProbabilityStorage(object sender, RoutedEventArgs e) {
        await Settings.CleanProbabilityStorageAsync(false);
    }
    private async void OnDiscardProbabilityStorage(object sender, RoutedEventArgs e) {
        if (Settings.ProbabilityStorage is not { } storage) return;
        var dialog = new ContentDialog { XamlRoot = XamlRoot, Title = storage.DiscardLabel,
            Content = storage.DiscardConfirmation, PrimaryButtonText = storage.ConfirmLabel,
            CloseButtonText = storage.CancelLabel, DefaultButton = ContentDialogButton.Close };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary) await Settings.CleanProbabilityStorageAsync(true);
    }
    private async void OnDisableTokenContribution(object sender, RoutedEventArgs e)
    {
        await Settings.SetTokenContributionAsync(false);
    }

    private async void OnTokenContribution(object sender, RoutedEventArgs e)
    {
        if (_tokenContributionDialogOpen || !Settings.TokenContributionControlsEnabled)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = Settings.TokenContributionHeading,
            Content = new ScrollViewer
            {
                Content = new TextBlock
                {
                    Text = string.Join("\n\n", Settings.TokenContributionDisclosure,
                        Settings.TokenContributionCaptureNote, Settings.TokenContributionScopeNote),
                    TextWrapping = TextWrapping.Wrap,
                },
            },
            PrimaryButtonText = Settings.TokenContributionConfirm,
            CloseButtonText = Settings.TokenContributionCancel,
            DefaultButton = ContentDialogButton.Close,
        };

        _tokenContributionDialogOpen = true;
        try
        {
            if (await DialogGuard.ShowOnceAsync(dialog) == ContentDialogResult.Primary)
            {
                await Settings.SetTokenContributionAsync(true, disclosureConfirmed: true);
            }
        }
        finally
        {
            _tokenContributionDialogOpen = false;
        }
    }

    private async void OnStartAtLoginToggled(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleSwitch toggle && Settings.IsLoaded)
        {
            await Settings.SetStartAtLoginAsync(toggle.IsOn);
        }
    }

    private async void OnConsentChanged(object sender, RoutedEventArgs e)
    {
        await Settings.SaveConsentAsync();
    }

    private async void OnProjectMode(object sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: ProjectSettingViewModel project })
        {
            await Settings.ToggleProjectAsync(project);
        }
    }

    /// <summary>
    /// The declaration switch. Written the moment it moves, like every other
    /// knob on this screen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nothing here waits on a restart: the daemon picks the declaration up on
    /// its next poll, which is what the line under the switch says.
    /// </para>
    /// <para>
    /// This also fires when the binding moves the switch, which a repaint
    /// driven by a daemon event now does. <c>SetRoutingEnabledAsync</c>
    /// refuses a write that matches what it already holds, and the view model
    /// sets its field before it notifies, so a repaint cannot write anything
    /// back through here.
    /// </para>
    /// </remarks>
    private async void OnRoutingToggled(object sender, RoutedEventArgs e)
    {
        if (sender is ToggleSwitch toggle && Settings.IsLoaded)
        {
            await Settings.SetRoutingEnabledAsync(toggle.IsOn);
        }
    }

    /// <summary>
    /// Rewrites the declaration from the port and folder boxes and asks
    /// again. Those two are written on this button rather than on every
    /// keystroke, which is why they are the only controls on this screen that
    /// are not live.
    /// </summary>
    private async void OnRoutingApply(object sender, RoutedEventArgs e)
    {
        await Settings.ApplyRoutingAsync();
    }

    /// <summary>
    /// The one press the discovered case costs: turn it on and check.
    /// </summary>
    /// <remarks>
    /// It declares the port that is on screen -- which discovery filled in,
    /// or whatever was typed over it -- rather than one rebuilt from the
    /// pointer, so a press cannot declare a number different from the one
    /// displayed.
    /// </remarks>
    private async void OnRoutingConnect(object sender, RoutedEventArgs e)
    {
        await Settings.ConnectRoutingAsync();
    }

    /// <summary>
    /// Asks what the machine knows again, for somebody who started IronWire
    /// after opening this window. It reads a file and declares nothing.
    /// </summary>
    private async void OnRoutingLookAgain(object sender, RoutedEventArgs e)
    {
        await Settings.LookAgainAsync();
    }

    /// <summary>
    /// Points this device at the witness in the three fields above.
    /// </summary>
    /// <remarks>
    /// The state is re-read from the ABI afterwards whether or not the write
    /// landed, so this card never shows a configuration that was asked for
    /// rather than one that is in force.
    /// </remarks>
    private async void OnWitnessConfigure(object sender, RoutedEventArgs e)
    {
        await Settings.ConfigureWitnessAsync();
    }

    /// <summary>
    /// Stops using a witness, returning this device to local redaction.
    /// </summary>
    /// <remarks>
    /// Not an off switch, and the sentence beside the button says so: the
    /// redaction still happens, here, and what changes is that later sessions
    /// carry this app's own judgement of what was left rather than a signed
    /// record of it.
    /// </remarks>
    private async void OnWitnessClear(object sender, RoutedEventArgs e)
    {
        await Settings.ClearWitnessAsync();
    }

    private async void OnBehaviorChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (!Settings.IsLoaded || Settings.IsBusy || double.IsNaN(args.NewValue))
        {
            return;
        }

        BehaviorSetting setting = sender.Name switch
        {
            "QuiescenceMinutes" => BehaviorSetting.QuiescenceMinutes,
            "ApprovalHoldSeconds" => BehaviorSetting.ApprovalHoldSeconds,
            "DigestHours" => BehaviorSetting.DigestHours,
            _ => throw new InvalidOperationException("unknown behavior setting"),
        };
        await Settings.SaveBehaviorAsync(setting, args.NewValue);
    }

    /// <summary>
    /// Going public.
    /// </summary>
    /// <remarks>
    /// <para>The toggle does not claim anything. It opens the consent dialog,
    /// which is where the handle is typed and the acknowledgement is given --
    /// a contributor cannot meaningfully acknowledge "my handle becomes
    /// public" and then be asked afterwards what the handle is.</para>
    ///
    /// <para>Abandoning the dialog puts the toggle back off. The toggle says
    /// whether a handle is on the roster, and closing without claiming has put
    /// none there; a toggle left on would be this window claiming a listing
    /// that does not exist. A successful claim never reaches that line,
    /// because the panel replaces the row the toggle lives in.</para>
    ///
    /// <para>Only the off-to-on edge opens anything. Putting the toggle back
    /// re-enters this handler, and without the guard that second pass would
    /// open the dialog again the moment the contributor declined it.</para>
    /// </remarks>
    private async void OnGoPublicToggled(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleSwitch toggle || !toggle.IsOn)
        {
            return;
        }

        if (!await GoPublicDialog.RunAsync(XamlRoot, ViewModel))
        {
            toggle.IsOn = false;
        }
    }

    private async void OnSaveProfile(object sender, RoutedEventArgs e)
    {
        await ViewModel.SaveAsync();
    }

    /// <summary>
    /// Leaving the roster.
    /// </summary>
    /// <remarks>
    /// Unconfirmed, and deliberately so. This is the withdrawal of a consent,
    /// not a deletion: it removes a handle from future snapshots and is
    /// reversible by claiming again, so putting a "are you sure" in front of
    /// it would make stopping being public harder than becoming public. The
    /// gate belongs on the way in, which is where <see cref="GoPublicDialog"/>
    /// is.
    /// </remarks>
    private async void OnLeaveRoster(object sender, RoutedEventArgs e)
    {
        await ViewModel.LeaveRosterAsync();
    }
}
